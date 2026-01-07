#!/bin/bash

sed_inplace(){
    local pattern="$1"
    shift
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "$pattern" "$@"
    else
        sed -i "$pattern" "$@"
    fi
}

# fix STELFTOOLS_PATH
sed_inplace 's/STELFTOOLS_PATH="[^"]*"/STELFTOOLS_PATH="\/path\/to\/stelftools\/"/g' *.py

# del directories to be used by scripts
rm -rf ./_tmpdir/man_datasets
rm -rf ./_tmpdir/link_order_list
rm -rf ./_tmpdir/dummy_bin
