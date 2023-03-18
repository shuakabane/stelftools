#!/bin/bash
stelftools_path=$(pwd)

pip3 install r2pipe
pip3 install termcolor
pip3 install pyfzf

cat <<EOS >> $HOME/.radare2rc
# stelftools
(stelftools; "#!pipe python3 $stelftools_path/r2_stelftools.py")
EOS
