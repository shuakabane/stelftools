#!/bin/bash
#CURRENT_PATH=$(pwd)
CURRENT_PATH=$(pwd | sed -e 's/\//\\\//g')

# fix STELFTOOLS_PATH
sed_inplace() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# fix STELFTOOLS_PATH
sed_inplace "s/STELFTOOLS_PATH=\"\/path\/to\/stelftools\/\"/STELFTOOLS_PATH=\"$CURRENT_PATH\/\"/g" *.py

# add directories to be used by scripts
#mkdir ./_tmpdir
mkdir ./_tmpdir/man_datasets
mkdir ./_tmpdir/link_order_list
mkdir ./_tmpdir/dummy_bin
