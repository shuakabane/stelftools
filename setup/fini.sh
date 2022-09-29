#!/bin/bash
# fix STELFTOOLS_PATH
sed -i 's/STELFTOOLS_PATH="\/[a-z/]*"$/STELFTOOLS_PATH="\/path\/to\/stelftools\/"/g' *.py
# del directories to be used by scripts
rm -rf ./_tmpdir/man_datasets
rm -rf ./_tmpdir/link_order_list
rm -rf ./_tmpdir/dummy_bin
