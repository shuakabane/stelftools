#!/bin/bash
stelftools_path=$(pwd)
ghidra_install_path=$1

if [ $# != 1 ]; then
  echo "Please input the directory in which you installed ghidra"
  exit 1
fi

# Create symbolic link for stelftools plugin for ghidra Pro
pushd $ghidra_install_path/Ghidra/Features/Python/ghidra_scripts/
ln -s $stelftools_path/ghidra_stelftools.py .
popd
