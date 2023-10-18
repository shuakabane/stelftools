#!/usr/bin/env python3
import os
import sys
import glob
import json
import argparse
import subprocess
import lief

def set_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-arch', help = 'input the architecture of the toolchain to brute force')
    parser.add_argument('-target', help = 'target path')
    parser.add_argument('-verbose', '-v', action='store_true')
    args = parser.parse_args()
    return args

def get_lief_bin_arch(target_path):
    t_arch_list = []
    _bin = lief.parse(target_path)
    _bin_arch = str(_bin.header.machine_type)
    if _bin_arch == 'ARCH.AARCH64':
        t_arch_list = ['arm64', 'AARCH64']
    elif _bin_arch == 'ARCH.ARM':
        t_arch_list = ['arm', 'armv4l', 'armv5l', 'armv6l', 'armv7l']
        #t_arch_list = ['arm', 'armv4l', 'armv4tl', 'armv5-eabi', 'armv5l', 'armv6-eabihf', \
        #        'armv6l', 'armv7-eabihf', 'armv7l', 'armv7m']
    elif _bin_arch == 'ARCH.ARCH_68K':
        t_arch_list = ['m68k']
    elif _bin_arch == 'ARCH.MIPS':
        t_arch_list = ['mips', 'mips32', 'mips64', 'mipsel', 'mips32el', 'mips64el']
    elif _bin_arch == 'ARCH.PPC':
        t_arch_list = ['powerpc', 'powerpc-440fp', 'powerpc-e300c3', 'powerpc-e500mc', 'ppc']
    elif _bin_arch == 'ARCH.PPC64':
        t_arch_list = ['ppc64']
    elif _bin_arch == 'ARCH.SH':
        t_arch_list = ['sh2', 'sh2eb', 'sh2elf', 'sh4']
    elif _bin_arch == 'ARCH.SPARC':
        t_arch_list = ['sparc']
    elif _bin_arch == 'ARCH.SPARCV9':
        t_arch_list = ['sparc64']
    elif _bin_arch == 'ARCH.i386':
        t_arch_list = ['i386', 'i486', 'i586', 'i686', 'x86', 'x86-core2', 'x86-i686']
    elif _bin_arch == 'ARCH.X86_64':
        t_arch_list = ['x86_64', 'amd64']
    else:
        print('[error] Unknown architecture %s : %s' % (_bin_arch, target_path))
        exit(-1)
    return t_arch_list

if __name__ == '__main__':
    TOOLCHAIN_CONFIG_DIR_PATH = "./toolchain_config/"
    args = set_args()
    target_arch = ''

    if args.target == None:
        print("error: please input target path")
        exit(-1)
    target_path = args.target

    # LIFE ARCH
    if args.arch == 'AUTO' or args.arch == None:
        t_arch_list = get_lief_bin_arch(target_path)
    else:
        t_arch_list = (args.arch).split(',')
    match_num_list = []
    for tc_cfg_path in sorted(glob.glob(TOOLCHAIN_CONFIG_DIR_PATH + "*.json")):
        with open(tc_cfg_path) as tc_cfg_fp:
            cfg_info = json.load(tc_cfg_fp)
        target_arch = cfg_info['arch']

        #if target_arch == args.arch:
        if target_arch in t_arch_list:
            #print(target_arch, t_arch_list)
            cmd = ["python3", "func_ident.py", "-cfg", tc_cfg_path, "-target", target_path]
            cmd_log = subprocess.run(cmd,stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            if len(cmd_log.stderr.decode("utf8")) != 0:
                #print(cmd_log.stderr.decode("utf8"))
                continue
            log_list = []
            for _log_line  in cmd_log.stdout.decode("utf8").split('\n'):
                log_list.append( (" ").join(_log_line.split(' ')[1:]) )
            match_num_list.append([tc_cfg_path, len(set(log_list))])
    _, best_match_num = sorted(match_num_list, reverse=True, key=lambda x: x[1])[0]

    if args.verbose == True:
        print("Number of most matched functions: %d" % best_match_num)
        print("Candidates for toolchain ->")
    for tc_cfg_path, match_num in sorted(match_num_list, reverse=True, key=lambda x: x[1]):
        if match_num == best_match_num or args.verbose == True:
            print('%s : %s : %d' % (target_path, tc_cfg_path, match_num))
            if args.verbose == False:
                exit(0)
