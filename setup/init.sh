#!/bin/bash
#CURRENT_PATH=$(pwd)
CURRENT_PATH=$(pwd | sed -e 's/\//\\\//g')

# fix STELFTOOLS_PATH
sed -i "s/STELFTOOLS_PATH=\"\/path\/to\/stelftools\/\"/STELFTOOLS_PATH=\"$CURRENT_PATH\/\"/g" func_ident.py
sed -i "s/STELFTOOLS_PATH=\"\/path\/to\/stelftools\/\"/STELFTOOLS_PATH=\"$CURRENT_PATH\/\"/g" DubMaker.py
sed -i "s/STELFTOOLS_PATH=\"\/path\/to\/stelftools\/\"/STELFTOOLS_PATH=\"$CURRENT_PATH\/\"/g" libfunc_info_create.py
# install the python3 package
pip3 install yara-python
pip3 install capstone
pip3 install pyelftools
pip3 install python-magic
pip3 install arpy
# add directories to be used by scripts
mkdir ./_tmpdir
mkdir ./_tmpdir/man_datasets
mkdir ./_tmpdir/link_order_list
mkdir ./_tmpdir/dummy_bin
