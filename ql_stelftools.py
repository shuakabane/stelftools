#!/usr/bin/env python3
## Usage
# python3 qi_stelftools.py -cfg {toolchain}.json -target /path/to/bin
# or
# python3 qi_stelftools.py -flist /path/to/result_of_libfunc_identification -target /path/to/bin

STELFTOOLS_PATH="/path/to/stelftools/"
STELFTOOLS_TOOLCHAIN_PATH = STELFTOOLS_PATH + "toolchain_config/"
QILING_PATH="/path/to/qiling/"

import os
import re
import sys
import subprocess

import lief
import argparse

from qiling import Qiling
from qiling.const import QL_VERBOSE

lfunc_dict = {}

def set_args():
    parser = argparse.ArgumentParser()
    # and matching
    parser.add_argument('-cfg', help = 'toolchain config path')
    parser.add_argument('-target', help = 'target path')
    # only trace
    parser.add_argument('-flist', help = 'libfunc identification result path')
    args = parser.parse_args()
    return args

def ident_lfunc(cfg_path, target_path):
    script_path = STELFTOOLS_PATH + 'func_ident.py'
    tc_cfg_path = STELFTOOLS_TOOLCHAIN_PATH + cfg_path
    run_cmd = [ \
            'python3', script_path, \
            '-cfg', tc_cfg_path, \
            '-target', target_path \
            ]
    cmd_res = subprocess.check_output(run_cmd).split(b'\n')
    fmt_list = [x.decode('utf-8') for x in cmd_res if x != b'']
    #print(fmt_list)
    for _fl in fmt_list:
        _addr, _name = _fl.split(' ')
        addr = int(_addr, 16)
        name = re.sub(',', '_OR_', _name)
        lfunc_dict[addr] = name
    return lfunc_dict

def load_lfunc_info(flist_path):
    with open(flist_path) as f:
        _line = f.readlines()
        for _l in _line:
            _addr, _name = _l.rstrip('\n').split(' ')
            addr = int(_addr, 16)
            name = re.sub(',', '_OR_', _name)
            lfunc_dict[addr] = name
    return lfunc_dict

def func_trace(ql: Qiling) -> None:
    ql_pc = ql.arch.regs.arch_pc
    if ql_pc in lfunc_dict.keys():
        print('call : %s (0x%lx)' % (lfunc_dict[ql_pc], ql_pc))
        #ql.log.info('call : %s (0x%lx)' % (lfunc_dict[ql_pc], ql_pc))

def get_lief_bin_rootfs(target_path):
    t_arch_rootfs = ''
    _bin = lief.parse(target_path)
    _bin_arch = str(_bin.header.machine_type)
    _bin_iclass = str(_bin.header.identity_class)
    _bin_idata = str(_bin.header.identity_data)

    if _bin_arch == 'ARCH.AARCH64':
        t_arch_rootfs = "examples/rootfs/arm64_linux"
    elif _bin_arch == 'ARCH.ARM':
        t_arch_rootfs = "examples/rootfs/arm_linux"
    elif _bin_arch == 'ARCH.MIPS':
        if _bin_iclass == str('ELF_CLASS.CLASS32'):
            if _bin_idata == str('ELF_DATA.LSB'):
                t_arch_rootfs = "examples/rootfs/mips32el_linux"
            else:
                t_arch_rootfs = "examples/rootfs/mips32_linux"
    elif _bin_arch == 'ARCH.i386':
        t_arch_rootfs = "examples/rootfs/x86_linux"
    elif _bin_arch == 'ARCH.RISCV':
        if _bin_iclass == str('ELF_CLASS.CLASS32'):
            t_arch_rootfs = "examples/rootfs/riscv32_linux"
        else:
            t_arch_rootfs = "examples/rootfs/riscv64_linux"
    elif _bin_arch == 'ARCH.x86_64':
        t_arch_rootfs = "examples/rootfs/x8664_linux"
    else:
        print('[error] Unknown architecture %s : %s' % (_bin_arch, target_path))
        exit(-1)
    return t_arch_rootfs

if __name__ == "__main__":
    args = set_args()
    cfg_path = args.cfg
    target_path = args.target
    flist_path = args.flist
    rootfs_path = QILING_PATH + get_lief_bin_rootfs(target_path)
    ql = Qiling( \
            [target_path], \
            rootfs_path, \
            verbose=QL_VERBOSE.OFF \
            )

    if cfg_path != None and target_path != None:
        lfunc_dict = ident_lfunc(cfg_path, target_path)
    elif flist_path != None and target_path != None:
        lfunc_dict = load_lfunc_info(flist_path)

    for addr in sorted(lfunc_dict.keys()):
        ql.hook_address(func_trace, addr)

    ql.run()
