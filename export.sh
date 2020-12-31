#!/bin/bash
cd /home/streamimir/myq_reversing

zim --export -o zim_html --format html --index-page index -O Notes/notebook.zim   --root-url https://xmppwocky.github.io/myq-gdo-reversing/ --template ZeroFiveEight
git add Notes zim_html
git commit -m "..."
git push
