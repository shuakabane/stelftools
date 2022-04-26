#!/bin/bash
stelftools_path=$(pwd)
ida_install_path=$1

if [ $# != 1 ]; then
  echo "Please input the directory in which you installed IDA Pro"
  exit 1
fi

# Create symbolic link for stelftools plugin for IDA Pro
pushd $ida_install_path/plugins
ln -s $stelftools_path/ida_stelftools.py .
ln -s $stelftools_path/func_ident.py .
ln -s $stelftools_path/DubMaker.py .
ln -s $stelftools_path/libfunc_mkrule.py .
ln -s $stelftools_path/libfunc_deparse.py .
ln -s $stelftools_path/libfunc_info_create.py .
popd
