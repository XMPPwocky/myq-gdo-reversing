import re, binascii, sys, struct
import logging

from pwn import *

context.arch = "thumb"
context.bits = 32
context.endian = "little"

def tubedbg(enabled):
    if enabled: logging.getLogger("pwnlib.tubes").setLevel(logging.DEBUG)
    else: logging.getLogger("pwnlib.tubes").setLevel(logging.INFO)

tube = serialtube(port=sys.argv[1], baudrate=115200)


FLASH_LINE_RE = re.compile(b"[0-9a-f]{8}: [0-9a-f]{8} [0-9a-f]{8}  [0-9a-f]{8} [0-9a-f]{8}")
def parse_line(l):
    if FLASH_LINE_RE.match(l):
        address, data = l.split(b":")
        address = int(address, 16)

        data = data.replace(b" ", b"")
        data = bytearray(binascii.unhexlify(data))

        for i in range(0, len(data), 4):
            data[i:i+4] = data[i:i+4][::-1]

        return address, data
    pass

MEM_LINE_RE = re.compile(b"[0-9A-F]{8}: [0-9A-F]{8}")



CHUNK_SIZE = 0x100
def dump_flash_chunk(addr):
    tube.clean()
    cmd = "flash read {:x} {:x}\r\n\n".format(addr, CHUNK_SIZE+0x100)
    tube.send(cmd)
    echoback = tube.recvuntil("Falsh read\n", timeout=1).strip()
    for i in range(CHUNK_SIZE // 0x10):
        resp = tube.recvuntil("\n", timeout=1).strip()
        parsed = parse_line(resp)
        if parsed is None:
            #print(repr(resp))
            raise ValueError("problem...")
        addr, data = parsed
        print("{:8x}: {:s}".format(addr, data.hex()))

    #print(resp)

    #tube.interactive()

#dump_flash_chunk(0x1000000)

def dump_flash_range(start, end):
    for i in range(start, end):
        while True:
            try:
                dump_flash_chunk(i)
                break
            except Exception as e:
                print("EXCEPTION, RETRY")
                print(e)
                continue


def read_mem_dw(addr):
    tube.clean()

    cmd = "DW {:x}\r\n\r\n".format(addr)
    tube.send(cmd)
    expected = "{:08X}: ".format(addr)
    #print(expected)
    resp_header = tube.recvuntil(expected, timeout=1)
    #print("r", resp)
    resp = tube.recvuntil("\n").strip()
    #print("r2", resp)

    return int(resp, 16)

def read_mem_chunk(addr, length):
    tube.clean()
    end = addr + length

    real_start_addr = addr - (addr % 4)
    real_end_addr = addr + length
    if real_end_addr % 4:
        real_end_addr += 4 - (real_end_addr % 4)

    dwords = {}


    for dw in range(real_start_addr, real_end_addr, 4):
        cmd = "DW {:0x}\r\n".format(dw)
        #print(cmd)
        tube.send(cmd)

    expected = "{:08X}: ".format(dw)
    resp = tube.recvuntil(expected, timeout=1) + tube.recvuntil(b"\n", timeout=1)
    for line in resp.split(b"\n"):
        line = line.strip()
        #print(line)
        if MEM_LINE_RE.match(line) is None: continue
        line_addr, line_dw = line.split(b":")
        line_addr = int(line_addr.strip(), 16)
        line_dw = int(line_dw.strip(), 16)
        #print("{:x} {:x}", line_addr, line_dw)
        dwords[line_addr] = line_dw

    #print(dwords)
    raw_data = b"".join([
        struct.pack("<I", dwords[dw_addr]) for dw_addr
        in range(real_start_addr,real_end_addr, 4)])

    return raw_data[addr - real_start_addr:][:length]


MEMCHUNK_SIZE=128
def read_mem_bytes(addr, length):
    out = b""
    for subaddr in range(addr, addr+length, MEMCHUNK_SIZE):
        while True:
            try:
                out += read_mem_chunk(subaddr, MEMCHUNK_SIZE)
                break
            except Exception as e:
                print(repr(e))
                print("EXCEPTION, RETRY")
                print(repr(e))
                continue
    return out

RSIP_REG_BASE = 0x48000600

def write_mem_dw(addr, dw):
    tube.clean()
    cmd = "EW {:0x} {:0x}\r\n".format(addr, dw)
    #print(cmd)
    tube.send(cmd)

    expected = "{:08X}: ".format(addr)
    print(expected)
    tube.recvuntil(expected, timeout=1)

def write_mem_bytes(addr, data):
    assert len(data) % 4 == 0

    tube.clean()

    for i in range(0, len(data), 4):
        dw = struct.unpack("<I", data[i:i+4])[0]
        cmd = "EW {:0x} {:0x}\r\n".format(addr + i, dw)
        tube.send(cmd)

    expected = "{:08X}: ".format(addr + i)
    print(expected)
    tube.recvuntil(expected, timeout=1)

def hd(s, *args, **kwargs):
    print(hexdump(s, *args, **kwargs))

def hexmem(addr, length=32):
    res = read_mem_bytes(addr, length)
    hd(res, begin=addr)
