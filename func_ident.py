#! /usr/bin/env python3

import glob
import re
import sys
import os
import struct
import yara
import argparse
import json
import hashlib
import subprocess

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.common import exceptions

import DubMaker

STELFTOOLS_PATH="/home/akabane/research/remote/stelftools/"

INIT_CRT_FUNC_LIST = ['__init', '_init', '.init', \
        '_start', '_start_c', '__start', 'hlt', '__gmon_start__', 'set_fast_math', \
        'deregister_tm_clones', 'register_tm_clones', '__do_global_dtors_aux', 'frame_dummy', \
        'call___do_global_dtors_aux', 'call_frame_dummy']
FINI_CRT_FUNC_LIST = ['__fini', '_fini', '.fini', \
        '__do_global_ctors_aux', '__get_pc_thunk_bx', 'call___do_global_ctors_aux']
skip_libc_func = ['abort', '_dl_start', 'fini', '_start', 'exit'] + INIT_CRT_FUNC_LIST
_CRT_INIT_LIST = ['__init', '_init', '.init']
_CRT_FINI_LIST = ['__fini', '_fini', '.fini']
TOP_LIBC_FUNC_LIST = set(['puts', 'fcntl', 'fcntl64', 'close', 'fork', 'vfork', \
        'getppid', 'open', 'time', 'closedir', 'opendir', 'readdir', '__fcntl_nocancel', \
        '__close_nocancel', 'sysconf', 'prctl', 'syscall', 'pipe', '__init_libc', \
        '__libc_start_init', 'libc_start_init', 'dummy', 'dummy1', '__aeabi_uidiv', \
        '__aeabi_uidivmod', '__divsi3', '__aeabi_idivmod', '__div0', 'memset', \
        'generic_start_main', '__libc_start_main', 'check_one_fd', '__libc_check_standard_fds', \
        '__libc_setup_tls', '__tls_get_addr', '__libc_csu_init', '__libc_csu_fini'])

GLIBC_BOT_LIBC_FUNC_LIST = ['free_mem']
MAX_PATTERN_LENGTH = 15000

def get_top_addr(functions, skip_libc_func):
    top_addr = 0
    for _addr in sorted(functions.keys()):
        if len(set(functions[_addr]['names']) & set(INIT_CRT_FUNC_LIST)) == 0 \
                and len(set(functions[_addr]['names']) & set(skip_libc_func)) == 0 \
                and len(set(functions[_addr]['names']) & set(TOP_LIBC_FUNC_LIST)) >= 1 \
                and functions[_addr]['size'] >= 10:
            top_addr = _addr
            break
    return top_addr
def get_bot_addr(functions):
    bot_addr = 0
    for _addr in list(reversed(sorted(functions.keys()))):
        if len(set(functions[_addr]['names']) & set(FINI_CRT_FUNC_LIST)) != 0:
            bot_addr = _addr + functions[_addr]['size']
            break
    if bot_addr == 0:
        for _addr in list(reversed(sorted(functions.keys()))):
            if len(set(functions[_addr]['names']) & set(GLIBC_BOT_LIBC_FUNC_LIST)) != 0:
                bot_addr = _addr + functions[_addr]['size']
                break
    if bot_addr == 0 and len(functions.keys()) != 0:
        bot_addr = sorted(functions.keys())[-1]
    #print(hex(bot_addr))
    return bot_addr
def libc_func_in_crt_area(functions, libc_area_top, skip_libc_func):
    skip_func_addr = []
    for _addr in sorted(functions.keys()):
        if _addr < libc_area_top:
            if len(set(functions[_addr]['names']) & set(skip_libc_func)) == len(set(functions[_addr]['names'])) \
                    or len(set(functions[_addr]['names']) & set(INIT_CRT_FUNC_LIST + FINI_CRT_FUNC_LIST)) == len(set(functions[_addr]['names'])):

                #print(functions[_addr]['names'], hex(_addr), '-', hex(_addr + functions[_addr]['size'] - 1)) # dbg
                skip_func_addr.append(_addr)
    #print(skip_func_addr)
    return skip_func_addr

def calc_libc_to_data_ratio(target_info, libc_area_top, libc_area_bot, skip_func_addr):
    func_num = 0
    target_area = []
    for i in range(target_info['size']):
        target_area.append(0)
    # print(hex(libc_area_top), hex(libc_area_bot))
    for addr in sorted(target_info['functions'].keys()): # pending function area
        if not addr in skip_func_addr:
            if libc_area_top != 0 and addr < libc_area_top:
                continue
            if libc_area_bot != 0 and addr > libc_area_bot:
                continue
            func_num += 1
            f_start = addr
            if not 'max_size' in target_info['functions'][addr].keys():
                f_end = target_info['functions'][addr]['size']+addr-1
            else:
                f_end = target_info['functions'][addr]['max_size']+addr-1
            for i in range(f_start, f_end+1):
                i -= target_info['base_vaddr']
                try:
                    target_area[i] = target_info['functions'][addr]['names']
                except IndexError:
                    continue
            continue
    no_match_area = 0
    #print(hex(libc_area_top - target_info['base_vaddr']), hex(libc_area_bot + 1 - target_info['base_vaddr']))
    for libc_area_hex in target_area[ \
            libc_area_top - target_info['base_vaddr']:libc_area_bot + 1 - target_info['base_vaddr']\
            ]:
        if libc_area_hex == 0:
            no_match_area += 1
    if (libc_area_bot - libc_area_top) == 0:
        return 0.00, [0x0, 0x0]
    bin_to_libc_ratio = 1 - (no_match_area / (libc_area_bot - libc_area_top + 1))
    return bin_to_libc_ratio, target_area

def output(target_info, target_path, output_mode):
    # get libc area top/bot address
    libc_area_top = get_top_addr(target_info['functions'], skip_libc_func)
    libc_area_bot = get_bot_addr(target_info['functions'])
    skip_func_addr = libc_func_in_crt_area(target_info['functions'], libc_area_top, skip_libc_func)
    #print("area :", hex(libc_area_top), '-', hex(libc_area_bot))

    if output_mode in ['no']:
        None
    # default output mode
    elif output_mode in ['compare', 'ida', 'ghidra']:
        match_info = {}
        matched_func_addrs = []
        for addr in sorted(target_info['functions'].keys()):
            #print('dbg :', target_info['functions'][addr])
            # skip
            if not addr in skip_func_addr:
                if libc_area_top != 0 and addr < libc_area_top:
                    continue
                if libc_area_bot != 0 and addr > libc_area_bot:
                    continue
            matched_func_addrs.append(addr)
            if output_mode == 'compare':
                match_func = ','.join([x for x in sorted(target_info['functions'][addr]['names'])])
            elif output_mode in ['ida', 'ghidra']:
                match_func = '_OR_'.join([x for x in sorted(target_info['functions'][addr]['names'])])
            #if len(set(target_info['functions'][addr]['names']) \
            #        & set(INIT_CRT_FUNC_LIST+FINI_CRT_FUNC_LIST)) >= 1:
            #    print(hex(addr), ': crt tp :', match_func, target_info['functions'][addr]['size'])
            if addr >= libc_area_top:
                if target_info['functions'][addr]['names'] != ['']:

                    print(hex(addr) + ':' + match_func)
                    match_info[addr] = {'names' : match_func}
        return match_info
    elif output_mode in ['default']:
        #print(hex(libc_area_top), '-', hex(libc_area_bot))
        matched_func_addrs = []
        for addr in sorted(target_info['functions'].keys()):
            #print('dbg :', target_info['functions'][addr])
            # # skip
            # if not addr in skip_func_addr:
            #     if libc_area_top != 0 and addr < libc_area_top:
            #         print('skip(a) :', target_info['functions'][addr])
            #         continue
            #     if libc_area_bot != 0 and addr > libc_area_bot:
            #         print('skip(b) :', target_info['functions'][addr])
            #         continue
            # if target_info['functions'][addr]['names'] == ['']:
            #     print('skip(c) :', target_info['functions'][addr])
            #     continue
            matched_func_addrs.append(addr)
            match_func = ','.join([x for x in sorted(target_info['functions'][addr]['names'])])
            print(hex(addr), match_func)
    elif output_mode in ['count']:
        print('%s : %d' % ( \
                target_path, \
                len(target_info['functions'].keys())
                ))
    else:
        print("[error] does not support output style : %s" % output_mode)
        exit(-1)

def get_bin_arch(target):
    try:
        e = ELFFile(target)
        arch = e['e_machine']
        if e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
            bit = 32
        elif e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
            bit = 64
        if e['e_ident']['EI_DATA'] == 'ELFDATA2LSB':
            endian = 'little'
        elif e['e_ident']['EI_DATA'] == 'ELFDATA2MSB':
            endian = 'big'
    except exceptions.ELFParseError as e: # ToDo
        # get arch for "readelf -h"
        arch = os.popen( \
                'LANG=CC llvm-readelf-13 -h ' + target.name + ' 2> /dev/null | grep Machine | tr -s " " | cut -f2     -d:' \
                ).read().strip() # TODO: do not use readelf
        # convert the architecture name obtained by readelf to capstone format
        if arch in ['AArch64']:
            arch = 'EM_AARCH64'
        elif arch in ['ARM']:
            arch = 'EM_ARM'
        elif arch in ['Intel 80386']:
            arch = 'EM_386'
        elif arch in ['MIPS R3000']:
            arch = 'EM_MIPS'
        elif arch in ['MC68000']:
            arch = 'EM_68K'
        elif arch in ['PowerPC']:
            arch = 'EM_PPC'
        elif arch in ['PowerPC64']:
            arch = 'EM_PPC64'
        elif arch in ['RISC-V']:
            arch = 'EM_RISCV'
        elif arch in ['Hitachi SH']:
            arch = 'EM_SH'
        elif arch in ['Sparc']:
            arch = 'EM_SPARC'
        elif arch in ['Sparc v9']:
            arch = 'EM_SPARCV9'
        elif arch in ['Advanced Micro Devices X86-64']:
            arch = 'EM_X86_64'
        # get magic bytes for "readelf -h"
        magic = os.popen( \
                'LANG=CC llvm-readelf-13 -h ' + target.name + ' 2> /dev/null | grep Magic | tr -s " " | cut -d":" -f2- | cut -c2- ').read().strip().split(' ') # TODO: do not use readelf
        # get bit
        if magic[4] == '01':
            bit = 32
        elif magic[4] == '02':
            bit = 64
        # get endian
        if magic[5] == '01':
            endian = 'little'
        if magic[5] == '02':
            endian = 'big'
    return arch, bit, endian

def get_inst_area(target, base_vaddr, t_bit):
    top_inst_addr = 0
    top_inst_addr = 0
    # pyelftools
    try: # pyelftools
        e = ELFFile(target)
        # get elf instruction area
        _sh_addr_list = []
        _last_sec_addr = 0x0
        for sec in e.iter_sections():
            if sec.header['sh_type'] == 'SHT_PROGBITS' and sec.header['sh_flags'] == 6:
                _sh_addr_list.append(sec.header['sh_addr'])
                #print(hex(sec.header['sh_addr']), hex(sec.header['sh_size']))
                if _last_sec_addr < sec.header['sh_addr']:
                    _last_sec_addr = sec.header['sh_addr']
                    bot_inst_addr = sec.header['sh_addr'] + sec.header['sh_size']
        if len(_sh_addr_list) != 0:
            if 0x0 > min(_sh_addr_list) - base_vaddr: # ToDo: fix worng code
                top_inst_addr = min(_sh_addr_list)
                bot_inst_addr = bot_inst_addr - 1
            else:
                top_inst_addr = min(_sh_addr_list) - base_vaddr
                bot_inst_addr = bot_inst_addr - base_vaddr - 1
            #print(hex(top_inst_addr), '~', hex(bot_inst_addr))
        #exit(-1)
    except exceptions.ELFParseError as e:
        None
    if top_inst_addr == bot_inst_addr == 0:
        if t_bit == 32:
             _load_addr = os.popen('LANG=CC llvm-readelf-13 -l ' + target.name + \
                     ' 2> /dev/null | grep "LOAD " | grep "R" | grep "E" | tr -s " " | cut -c2-' \
                     ).read().split('\n')[:-1]
             if _load_addr == []:
                 _load_addr = os.popen('LANG=CC readelf -l ' + target.name + \
                         ' 2> /dev/null | grep "LOAD " | grep "R" | grep "E" | tr -s " " | cut -c2-' \
                         ).read().split('\n')[:-1]
             load_addr = _load_addr[0]
             top_inst_addr = int(load_addr.split(' ')[3], 16) - base_vaddr
             bot_inst_addr = top_inst_addr + int(load_addr.split(' ')[4], 16)
        elif t_bit == 64:
             _load_addr = os.popen('LANG=CC llvm-readelf-13 -l ' + target.name + \
                     ' 2> /dev/null | grep -A 1 "LOAD " | grep "R E" | tr -s " " | tr -d "\n" | cut -c2-' \
                     ).read().split('\n')[:-1]
             if _load_addr != []:
                 load_addr =  _load_addr[0]
             else:
                 load_addr = os.popen('LANG=CC readelf -l ' + target.name + \
                         ' 2> /dev/null | grep -A 1 "LOAD " | cut -d":" -f2- | cut -d"-" -f2- | grep -B 1 -e "R E" -e "RWE" | grep -v "\-\-" | tr -s " " | cut -c2- | tr -s "\n" " "' + " | sed -e 's/LOAD/_/g'" \
                         ).read().split('_')[1]

             top_inst_addr = int(load_addr.split(' ')[3], 16) - base_vaddr
             bot_inst_addr = top_inst_addr + int(load_addr.split(' ')[4], 16)

    #print(hex(top_inst_addr), hex(bot_inst_addr))
    #exit(-1)
    return top_inst_addr, bot_inst_addr

def capstone_disasm_bin(target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr):
    target_inst = {}
    # set capstone md
    if t_arch in ['EM_AARCH64']:
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_386']:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif t_arch in ['EM_X86_64']:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif t_arch in ['EM_ARM']:
        if t_endian == 'big':
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN) # armeb
        elif t_endian == 'little':
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN) # arml, armle
        #md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS) # cortexm
    elif t_arch in ['EM_MIPS']: # not check
        if t_bit == 32:
            if t_endian == 'big':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
            elif t_endian == 'little':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        elif t_bit == 64:
            if t_endian == 'big':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)
            elif t_endian == 'little':
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_68K']:
        md = Cs(CS_ARCH_M68K, CS_MODE_M68K_040)
        md.skipdata = True
    elif t_arch in ['EM_PPC']:
        if t_endian == 'big':
            md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
        elif t_endian == 'little':
            md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_PPC64']:
        if t_endian == 'big':
            md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN)
        elif t_endian == 'little':
            md = Cs(CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
    elif t_arch in ['EM_RISCV']:
        if t_bit == 32:
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
        elif t_bit == 64:
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    elif t_arch in ['EM_SPARC']:
        md = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN)
    elif t_arch in ['EM_SPARCV9']:
        md = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN + CS_MODE_V9)
    else:
        print("[disasm/capstone] Not support arch : %s " % t_arch, file = sys.stderr)
        exit(-1)
    md.skipdata = True
    md.detail = True
    target.seek(top_inst_addr)
    target_code = target.read()
    for i in md.disasm(target_code, top_inst_addr):
        if i.address >= top_inst_addr and i.address <= bot_inst_addr:
            target_inst[i.address] = i
        elif bot_inst_addr != 0 and i.address > bot_inst_addr:
            break
    return target_inst

def objdump_disasm_bin(target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr):
    target_inst = {}
    target_path = target.name
    # objdump path
    if t_arch in ['EM_ARC_COMPACT']:
        #Set the path of objdump that supports the arc architecture.
        OBJDUMP_PATH = \
                "/path/to/arc objdump"
    elif t_arch in ['EM_SH']:
        #Set the path of objdump that supports the sh4 architecture.
        OBJDUMP_PATH = \
                "/path/to/sh4 objdump"
    objdump_res = subprocess.run([OBJDUMP_PATH, '-d', target_path], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for d_line in objdump_res.stdout.split('\n'):
        # del blank line
        if d_line == '':
            continue
        if re.search("^[ ]+[0-9a-fA-F]+", d_line) == None:
            continue
        _addr = int(re.sub('[\s+|:]', '', d_line.split('\t')[0]), 16)
        _hex = [_h for _h in (d_line.split('\t')[1].split(' ')) if _h != '']
        _inst = ' '.join([_i for _i in (d_line.split('\t')[2:]) if _i != ''])
        #print(hex(_addr), _hex, _inst)
        target_inst[_addr] = {'bytecode': _hex, 'inst': _inst}
    return target_inst

def parse_inst(target, target_inst, base_vaddr, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr):
    func_addr = []
    call_map = []

    got_addr_resolve_map = []
    readelf_got_map = []
    if t_arch in ['EM_MIPS']:
        got_addr_map = []
        readelf_got_list = os.popen( \
                "llvm-readelf-13 -A " + target.name + \
                " 2> /dev/null | sed -n '/ Local entries:/,$p' | sed '1,2d' | sed '$d' | sed -e 's/(gp)//g' | tr -d '-' | cut -c3- " \
                ).read().split('\n')[:-1]
        for readelf_got in readelf_got_list:
            readelf_got_map.append(readelf_got.split())

    #inst_addrs = sorted([k for k, v in target_inst.items()])
    inst_addrs = sorted(target_inst.keys())
    for addr in inst_addrs:
        i = target_inst[addr]
        if t_arch in ['EM_AARCH64', 'EM_ARM']: # aarch64
            if i.mnemonic == 'bl' or i.mnemonic == 'blls' \
                    or i.mnemonic == 'blne' or i.mnemonic == 'b' \
                    or i.mnemonic == 'bx' and i.op_str.startswith('#0x'):
                call_addr = int(re.sub('^#',  '', i.op_str), 16)
                if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                    func_addr.append(call_addr)
                    #print(hex(i.address), i.size, hex(call_addr))
                    call_map.append([ \
                            i.address, i.size, call_addr \
                            ])
        # i386, x86, x86-64
        elif t_arch in ['EM_386', 'EM_X86_64', 'EM_SPARC', 'EM_SPARCV9']: # ix86, x86_64, sparc
            if (i.mnemonic == 'call' and i.op_str.startswith('0x')) \
                    or (i.mnemonic == 'jmp' and i.op_str.startswith('0x') \
                    and len(i.bytes) == 5):
                call_addr = int(i.op_str, 16)
                if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                    #print(hex(i.address), i.size, hex(call_addr))
                    func_addr.append(call_addr)
                    call_map.append([ \
                            i.address, i.size, call_addr \
                            ])
        elif t_arch in ['EM_68K']:
            if (i.mnemonic == 'bsr.l' or i.mnemonic == 'bsr.w' or i.mnemonic == 'bsr.s') \
                    and i.op_str.startswith('$'):
                if i.mnemonic == 'bsr.l':
                    inst_size = 6
                elif i.mnemonic == 'bsr.w':
                    inst_size = 4
                elif i.mnemonic == 'bsr.s':
                    inst_size = 2
                call_map.append([ \
                        i.address, inst_size, int(re.sub('^\$', '0x', i.op_str), 16) \
                        ])
        elif t_arch in ['EM_MIPS']: # mips, mipsel, mips64, mips64el
            try:
                if (i.mnemonic == 'lw' \
                        and re.search("\(\$gp\)$", i.op_str) != None) \
                        or ( i.mnemonic == 'ld' \
                        and (re.search("\(\$gp\)$", i.op_str) != None \
                        or re.search("\(\$a.\)$", i.op_str) != None)):
                    ref_got_offset = int( \
                            re.sub('-', '', i.op_str.split(' ')[1]).split('(')[0], \
                            16 \
                            )
                    got_addr_map.append([i.address, i.size, ref_got_offset])
                    #print(hex(i.address), i.size, hex(ref_got_offset), 'a')
                    got_addr_resolve_map.append([ \
                            i.address, i.size, ref_got_offset \
                            ])
            except ValueError:
                continue
            # for inst_addr, inst_size, ref_got_offset in list(map(list, set(map(tuple, got_addr_resolve_map)))):
            #     for got_addr, got_offset, callee_addr in readelf_got_map:
            #         if ref_got_offset == int(got_offset):
            #             if not [inst_addr, inst_size, int(callee_addr, 16)] in call_map:
            #                 #print([hex(inst_addr), inst_size, hex(int(callee_addr, 16))])
            #                 call_map.append([inst_addr, inst_size, int(callee_addr, 16)])
            #                 func_addr.append(callee_addr)
        elif t_arch in ['EM_PPC', 'EM_PPC64']: # powerpc, powerpc64
            #print(i)
            if i.mnemonic == 'bl': # or i.mnemonic == 'b':
                call_addr = int(i.op_str, 16)
                if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                    func_addr.append(call_addr)
                    #print(hex(i.address), i.size, hex(call_addr))
                    call_map.append([i.address, i.size, call_addr])
        elif t_arch in ['EM_RISCV']: # risc-v-32, risc-v-64
            if i.mnemonic == 'jal':# or i.mnemonic == 'j':
                if i.op_str.startswith('0x'):
                    call_addr = addr + int(i.op_str, 16)
                    if call_addr >= top_inst_addr and call_addr <= bot_inst_addr:
                        func_addr.append(call_addr)
        elif t_arch in ['EM_ARC_COMPACT']:
            i_mnemonic = i['inst'].split(' ')[0]
            if i_mnemonic in ['b', 'b.d', 'bl', 'bl.d', 'breq', 'beq.d'] and '+0x' not in i['inst']:
                size = int(len("".join(i['bytecode']))/2)
                call_addr = int(i['inst'].split(';')[1].split(' ')[0], 16)
                func_addr.append(call_addr)
                call_map.append([addr, size, call_addr])
                #print(hex(addr), size, i['inst'], hex(call_addr))
        elif t_arch in ['EM_SH']:
            #print(hex(addr), i)
            i_mnemonic = i['inst'].split(' ')[0]
            if i_mnemonic in ['mov.l'] and '!' in i['inst']:
                size = int(len("".join(i['bytecode']))/2)
                call_addr = int(i['inst'].split('!')[1].split(' ')[1], 16)
                func_addr.append(call_addr)
                call_map.append([addr, size, call_addr])
                #print(hex(addr), size, i['inst'], hex(call_addr))
        else:
            print("[disasm/capstone] Not support arch : %s " % t_arch, file = sys.stderr)
            exit(-1)

    if t_arch in ['EM_MIPS']: # mips, mipsel, mips64, mips64el
        for inst_addr, inst_size, ref_got_offset in list(map(list, set(map(tuple, got_addr_resolve_map)))):
            for got_addr, got_offset, callee_addr in readelf_got_map:
                if ref_got_offset == int(got_offset):
                    if not [inst_addr, inst_size, int(callee_addr, 16)] in call_map:
                        #print([hex(inst_addr), inst_size, hex(int(callee_addr, 16))])
                        call_map.append([inst_addr, inst_size, int(callee_addr, 16)])
                        func_addr.append(callee_addr)
        # fmt call instruction address
        for _idx in range(len(call_map)):
            call_map[_idx][0] += base_vaddr
    elif t_arch in ['EM_SH']:
        None
    else:
        for _idx in range(len(call_map)):
            # fmt call instruction address
            call_map[_idx][0] += base_vaddr
            call_map[_idx][2] += base_vaddr
    return call_map

def get_func_addr(target, base_vaddr):
    # get information about the architecture
    t_arch, t_bit, t_endian = get_bin_arch(target)
    #print(t_arch, t_bit, t_endian)
    # get instruction area
    top_inst_addr, bot_inst_addr = get_inst_area(target, base_vaddr, t_bit)
    #print('->', hex(top_inst_addr), hex(bot_inst_addr))
    # # get instruction
    if not t_arch in ['EM_ARC_COMPACT', 'EM_SH']:
        target_inst = capstone_disasm_bin (target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr)
    else:
        target_inst = objdump_disasm_bin(target, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr)
    #exit(-1)
    # get function address
    call_map = parse_inst(target, target_inst, base_vaddr, t_arch, t_bit, t_endian, top_inst_addr, bot_inst_addr)
    #print('---')
    #for cm1, cm2, cm3 in sorted(call_map):
    #    print(hex(cm1), cm2, hex(cm3))
    #exit(-1)
    return call_map, top_inst_addr, bot_inst_addr

def get_symtab_info_by_capstone(target):
    symtab_info = []
    offset = 0
    size = 0
    vaddr = 0
    PH_EXEC = 0x1
    PH_WRITE = 0x2
    PH_READ = 0x4
    with open(target, 'rb') as f:
        e = ELFFile(f)
        for s in e.iter_segments():
            if s.header['p_type'] != 'PT_LOAD':
                continue
            # exclude other section
            if s.header['p_flags'] & PH_EXEC == 0 or s.header['p_flags'] & PH_READ == 0:
                continue
            offset = s.header['p_offset']
            size   = s.header['p_filesz']
            vaddr  = s.header['p_vaddr']
            symtab_info.append((offset, offset + size, vaddr - offset))
    return symtab_info

def get_symtab_info_by_reaelf(target):
    symtab_info = []
    arch = os.popen('LANG=CC readelf -h ' + target + ' 2> /dev/null | grep Machine | tr -s " " | cut -f2 -d:').read().strip() # TODO: do not use readelf
    bit = os.popen('LANG=CC readelf -h ' + target + ' 2> /dev/null | grep Class | tr -s " " | cut -f2 -d:').read().strip() # TODO: do not use readelf
    entryaddr = int(os.popen('LANG=CC readelf -h ' + target + ' 2> /dev/null | grep Entry | tr -s " " | cut -f2 -d:').read(), 16) # TODO: do not use readelf
    if bit == 'ELF32':
        seginfo = os.popen('LANG=CC readelf -l ' + target + ' 2> /dev/null | grep LOAD | tr -s " "').read().split('\n')[:-1] # TODO: do not use readelf
        for s in seginfo:
            info = s.split(' ')
            offset = int(info[2], 16)
            size = int(info[5], 16)
            vaddr = int(info[3], 16)
            symtab_info.append((offset, offset + size, vaddr))
    elif bit == 'ELF64':
        seginfo_lines = os.popen('LANG=CC readelf -l ' + target + ' 2> /dev/null | grep -A 1 -n LOAD | cut -d":" -f2- | cut -d"-" -f2- | tr -s " " | cut -c2-  | tr -s "\n" " " ').read().split('LOAD')[1:]
        for seginfo in seginfo_lines:
            if 'R' in seginfo and 'E' in seginfo or 'RE' in seginfo:
                info = seginfo.split(' ')
                offset = int(info[1], 16)
                size = int(info[4], 16)
                vaddr = int(info[2], 16)
                symtab_info.append((offset, offset + size, vaddr - offset))
    return symtab_info

def format_match_res(match_res, symtab_info, risc_v_flag):
    functions = {}
    #print(match_res)
    for m in match_res:
        ##if yara-python <= 4.2.3
        #for addr, _, match_ptn in m.strings:
        # else yara-python > 4.2.3
        # document: https://yara.readthedocs.io/en/v4.3.0/yarapython.html
        for strs_m in m.strings:
            for strs_m_inst in strs_m.instances:
                addr = strs_m_inst.offset
                match_len = strs_m_inst.matched_length
                if int(m.meta['size']) > MAX_PATTERN_LENGTH or risc_v_flag == False:
                    matched_len = int(m.meta['size'])
                for begin, end, vaddr in symtab_info:
                    if begin <= addr < end or begin == end == 0:
                        addr += vaddr
                        # fix risc-v relaxation size
                        if 'hex_only_num' in m.meta.keys() and (matched_len % 4) != 0:
                            matched_len = (matched_len // 4) * 4
                            #matched_len = (matched_len // 4) * 4 + 4
                        if addr in functions:
                            # exclude risc-v mismatch many relaxation function
                            if 'hex_only_num' in m.meta.keys():
                                if matched_len > int(m.meta['hex_only_num']):
                                    continue
                            if functions[addr]['size'] < matched_len: # overwrite big func info
                                functions[addr]['names'] = [x for x in m.meta['aliases'].split(', ')]
                                functions[addr]['size'] = matched_len
                                functions[addr]['detected'] = True
                            elif functions[addr]['size'] == matched_len:
                                functions[addr]['names'].extend([x for x in m.meta['aliases'].split(', ')])
                        else:
                            #if 'hex_only_num' in m.meta.keys():
                            #    if int(m.meta['hex_only_num']) % 4 != 0:
                            #        matched_len = (int(m.meta['hex_only_num']) // 4) * 4 + 4
                            functions[addr] = { \
                                    'names': [x for x in m.meta['aliases'].split(', ')], \
                                    'size' : matched_len, \
                                    'detected' : True, \
                                    'category' : 'library function'
                                    }
            #print(hex(addr), matched_len, ':', m.meta, functions[addr])
    return functions

def yara_matching(rules, target):
    data = _get_target_data(target)
    yara.set_config(max_match_data=MAX_PATTERN_LENGTH)
    match_res = rules.match(data=data)
    return match_res

def _get_target_data(f):
    f.seek(0)
    return f.read()

def get_target_fp(target_path):
    if not os.path.exists(target_path):
        print('%s : No such target file' % (target_path), file=sys.stderr)
        exit(-1)
    target = open(target_path, 'rb')
    return target

#def marge_nomatch_functions(_functions, call_map, base_vaddr):
def marge_nomatch_functions(_functions, call_map):
    # add addresses to the dict that do not have a pattern match from the function being called
    _exclude_addr_list = []
    for _, _, _c_addr in call_map:
        #call_addr = _c_addr + base_vaddr
        call_addr = _c_addr# + base_vaddr
        if not call_addr in _functions.keys():
            #_functions[call_addr] = {}
            _functions[call_addr] = { \
                    'names': [''], \
                    'size' : 0, \
                    'detected' : True, \
                    'category' : 'unmatch'
                    }
    _func_addr_list = sorted(_functions.keys())
    for _idx, _addr in enumerate(_func_addr_list):
        if _functions[_addr] == {} and _idx != 0:
            _prev_addr = _func_addr_list[_idx-1]
            try:
                if _addr < _prev_addr + _functions[_prev_addr]['size']:
                    _exclude_addr_list.append(_addr)
            except KeyError:
                continue
    # exclude address other than the first address of the function
    for _exclude_addr in _exclude_addr_list:
        del _functions[_exclude_addr]
    return _functions

def marge_functions(functions, _functions):
    _func_addr_list = sorted(functions.keys())
    for _addr in _func_addr_list:
        if functions[_addr]['names'] != ['']:
            continue
        if _addr in _functions.keys():
            functions[_addr] = _functions[_addr]
    return functions

# Todo : fix the hardcode point
def get_yara_rule(yara_rule_path, r_type, r_length):
#def get_yara_rule(yara_rule_path, rule_length, start_rule_length):
    risc_v_flag = False

    use_rule_list = []
    all_rule_line = []
    with open(yara_rule_path, 'r') as yfp:
        for rule_line in yfp:
            rule_line_fmt = rule_line.replace('\n', '')
            all_rule_line.append(rule_line_fmt)
    rule_version = all_rule_line[0].split(' ')[4]
    if rule_version == '0.2.0_2021_07_29':
        for line_index, yara_rule_line in enumerate(all_rule_line):
            if yara_rule_line.startswith('rule'):
                y_pattern = str(all_rule_line[line_index+7].strip('\t').strip('$pattern = {').strip(' }'))
                # get yara rule real length
                fmt_y_pattern = re.sub('(?<=\().*?(?=\))', 'XX', y_pattern).split(' ')
                y_pattern_length = len(fmt_y_pattern) - fmt_y_pattern.count('??') # pattern len - wildcard len
                # get yara rule type
                fmt_r_type = str(all_rule_line[line_index+3].strip('\t').replace('type = \"', '').replace('\"', ''))
                r_func_list = sorted(all_rule_line[line_index+2].strip('\t').split('\"')[1].split(' '))
                #print(r_func_list)
                if fmt_r_type == r_type and y_pattern_length >= r_length \
                        or len(set(_CRT_INIT_LIST + _CRT_FINI_LIST) & set(r_func_list)) > 0:
                    for index in range(11):
                        use_rule_list.append(all_rule_line[line_index+index])
    else: # default yara format
        use_rule_list = all_rule_line
    rule_str = '\n'.join(use_rule_list)
    use_rule_list = yara.compile(source=rule_str)
    return use_rule_list, risc_v_flag

def del_mismatch(functions):
    def del_mismatch_minimal_func(functions):
        _deleted_key = []
        for addr in sorted(set(functions.keys())):
            # exlude delete key
            if addr in _deleted_key:
                continue
            #print(addr, hex(addr), functions[addr])
            for in_offset in range(addr, addr+functions[addr]['size']):
                if in_offset != addr and in_offset in functions.keys():
                    #print('del(mini) :', hex(in_offset), functions[in_offset], '<-', hex(addr), functions[addr])
                    if functions[in_offset]['size'] > functions[addr]['size']:
                        continue
                    del functions[in_offset] # delete mismatch minimal function
                    _deleted_key.append(in_offset)
        return functions

    def del_mismatch_of_userdef_func(functions):
        top_libc_addr = 0
        # get top libc functions addr
        sort_functions_addr = sorted(functions.keys())
        for _idx, addr in enumerate(sort_functions_addr):
            if len(set(functions[addr]['names']) & TOP_LIBC_FUNC_LIST) >= 1 \
                    and functions[addr]['size'] >= 12 and len(functions[addr]['names']) <= 6: # ToDo
                top_libc_addr = addr
                #print(hex(top_libc_addr), functions[top_libc_addr])
                #exit(-1)
                break
        # delete mismatch functions
        for addr in sorted(functions.keys()):
            if len(set(functions[addr]['names']) & set(INIT_CRT_FUNC_LIST)) >= 1:
                #print(hex(addr), functions[addr])
                continue
            if addr == top_libc_addr:
                break
            #print('del(user) :', hex(addr), functions[addr])
            del functions[addr] # delete mismatch minimal function
        return functions

    def del_mismatch_below_crt(functions):
        current_fini_crt_func_name = []
        fin_crt_addr = 0
        fin_fin_crt_func = ['__fini', '_fini', '.fini']
        # case 1
        for addr in sorted(functions.keys()):
            if len(set(functions[addr]['names']) & set(FINI_CRT_FUNC_LIST)) == len(functions[addr]['names']):
                fin_crt_addr = addr
                for _addr in sorted(functions.keys()):
                    if addr < _addr:
                        if len(set(functions[_addr]['names']) & set(FINI_CRT_FUNC_LIST)) > 0:
                            fin_crt_addr = _addr
                        else:
                            break
                break
        if fin_crt_addr != 0:
            for addr in sorted(functions.keys()):
                if addr > fin_crt_addr:
                    if len(set(functions[addr]['names']) & set(FINI_CRT_FUNC_LIST)) == len(functions[addr]['names']) \
                            and len(set(functions[addr]['names']) & set(current_fini_crt_func_name)) != len(functions[addr]['names']):
                                #print(current_fini_crt_func_name)
                                current_fini_crt_func_name += functions[addr]['names']
                                continue
                    #print('del(b_crt) :', hex(addr), functions[addr])
                    del functions[addr]
        # del mismatch fini crt
        fin_fini_crt_func_addr = 0
        for addr in reversed(sorted(functions.keys())):
            if len(set(functions[addr]['names']) & set(fin_fin_crt_func)) == len(functions[addr]['names']):
                fin_fini_crt_func_addr = addr
        if fin_fini_crt_func_addr != 0:
            for addr in reversed(sorted(functions.keys())):
                if addr > fin_fini_crt_func_addr:
                    #print('del(f_crt) :', hex(addr), functions[addr])
                    del functions[addr]
                else:
                    break
        return functions

    def del_mismatch_many_addr(functions):
        _delete_key = []
        func_num = {}
        for addr in functions.keys():
            _link_func_name = ",".join(functions[addr]['names'])
            if _link_func_name == '':
                continue
            if _link_func_name in func_num.keys():
                func_num[_link_func_name] = func_num[_link_func_name] + 1
            else:
                func_num[_link_func_name] = 1
        for _link_func_name in func_num.keys():
            _list_func_name = _link_func_name.split(',')
            # skip glibc 'free_mem' function
            if len(set(_list_func_name) & set(GLIBC_BOT_LIBC_FUNC_LIST)) == len(set(_list_func_name)):
                continue
            duplic_match_num = func_num[_link_func_name] / len(_list_func_name)
            if duplic_match_num > 5:
                #print(_link_func_name, ':', func_num[_link_func_name], duplic_match_num)
                for addr in functions.keys():
                    if functions[addr]['names'] == _list_func_name:# and functions[addr]['size'] <= 12:
                        #print('del', hex(addr), functions[addr])
                        _delete_key.append(addr)
            elif duplic_match_num > 2:
                for addr in functions.keys():
                    if functions[addr]['size'] < 20 and functions[addr]['names'] == _list_func_name:# and functions[addr]['size'] <= 12:
                        #print('del', hex(addr), functions[addr])
                        _delete_key.append(addr)
        # delete key
        for _del_addr in sorted(set(_delete_key)):
            #print('del(many) :', hex(_del_addr), functions[_del_addr])
            del functions[_del_addr]
        return functions

    # delete unmatch address
    for _addr in sorted(functions.keys()):
        if functions[_addr]['category'] == 'unmatch':
            del functions[_addr]

    # delete mismatched patterns outside the libc range
    #functions = del_outside_the_libc_area(functions, top_inst_addr, bot_inst_addr)
    # delete mismatched minimal function
    functions = del_mismatch_minimal_func(functions) # a
    ## delete mismatch of the user define function
    #functions = del_mismatch_of_userdef_func(functions) # b
    ## delete mismatch of the
    #functions = del_mismatch_below_crt(functions) # c
    ## ToDo : Implement a function to delete functions that match more than 10 address and have short patterns.
    #functions = del_mismatch_many_addr(functions)
    return functions

def get_alias_list(alias_list_path):
    alias_list = []
    with open(alias_list_path, 'rt') as al_fp:
        for alias in al_fp.readlines():
            alias_list.append(alias.rstrip('\n').split(','))
    return alias_list

def del_alias(functions, alias_list):
    for _addr in sorted(functions.keys()):
        # skip
        if len(functions[_addr]['names']) == 1:
            continue
        for alias in alias_list:
            compare_list = sorted(set(functions[_addr]['names']) & set(alias))
            no_compare_list = sorted(set(functions[_addr]['names']) - set(alias))
            # phase 1: delete all alias
            if len(compare_list) == len(functions[_addr]['names']):
                #print('alias match 1 :', functions[_addr]['names'], '->', [ min(alias, key=len) ] )
                functions[_addr]['names'] = [min(compare_list, key=len)]
            # phase 2:
            elif len(compare_list) > 1:
                #print('alias match 2 :', functions[_addr]['names'], '->', [ min(alias, key=len) ] + no_compare_list)
                functions[_addr]['names'] = sorted([min(compare_list, key=len)] + no_compare_list)
        #print(hex(_addr), functions[_addr]['names'])
    return functions

def _match_array_index_list(_list, func_name_list):
    index_list= []
    for func_name in func_name_list:
        index_list.extend(_match_array_index(_list, func_name))
    return sorted(set(index_list))
def _match_array_index(_list, func_name):
    return sorted(set([index for index, _func_name in enumerate(_list) if _func_name == func_name]))

def link_order_base_identificate(functions, alias_list, func_link_order_list):
    #SEARCH_DEPTH = 10
    SEARCH_DEPTH = 5
    MAX_AREA_LENGTH = 15
    matched_func_num = 0
    libfunc_addr_list = []
    multi_libfunc_addr_list = []
    matched_func_dict = {}
    for addr, funcs in functions.items():
        #print(addr, funcs)
        libfunc_addr_list.append(addr)
        if funcs['detected'] == True and len(funcs['names']) > 1:
            multi_libfunc_addr_list.append(addr)

    libfunc_addr_list = sorted(libfunc_addr_list)
    multi_libfunc_addr_list = sorted(multi_libfunc_addr_list)

    #print('\n-----------\n')
    for multi_func_addr in multi_libfunc_addr_list:
        match_func_list = []
        #print('---')
        #print('main ->' ,hex(multi_func_addr), functions[multi_func_addr])
        #print(functions[multi_func_addr]['names']) # dbg
        candidate_func_index = libfunc_addr_list.index(multi_func_addr)
        base_top_func_addr = 0
        base_bot_func_addr = 0
        base_top_func_alias_list = []
        base_bot_func_alias_list = []
        for i in range(1, SEARCH_DEPTH+1):
            if base_top_func_addr != 0 and base_bot_func_addr != 0:
                break
            try:
                top_func_addr = libfunc_addr_list[candidate_func_index - i]
                bot_func_addr = libfunc_addr_list[candidate_func_index + i]
            except IndexError:
                continue

            #print(top_func_addr)
            #print(bot_func_addr)
            #print('-')
            if base_top_func_addr == 0:
                if len(functions[top_func_addr]['names']) == 1:
                    _top_alias = []
                    base_top_func_alias_list = []# reinitialized list
                    for alias in alias_list:
                        if functions[top_func_addr]['names'][0] in alias:
                            _top_alias.extend(alias)
                    if len(_top_alias) != 0:
                        base_top_func_alias_list = sorted(set(_top_alias))
                    else:
                        base_top_func_alias_list = [functions[top_func_addr]['names'][0]]
                    #func_link_order_list check
                    exists_flag = False
                    for base_top_func_alias in base_top_func_alias_list:
                        if base_top_func_alias in func_link_order_list:
                            exists_flag = True
                    if exists_flag == True:
                        base_top_func_addr = top_func_addr
                        #print('top:', hex(base_top_func_addr), base_top_func_alias_list)
            if base_bot_func_addr == 0:
                if len(functions[bot_func_addr]['names']) == 1:
                    _bot_alias = []
                    base_bot_func_alias_list = []# reinitialized list
                    for alias in alias_list:
                        if functions[bot_func_addr]['names'][0] in alias:
                            _bot_alias.extend(alias)
                    if len(_bot_alias) != 0:
                        base_bot_func_alias_list = sorted(set(_bot_alias))
                    else:
                        base_bot_func_alias_list = [functions[bot_func_addr]['names'][0]]
                    #func_link_order_list check
                    exists_flag = False
                    for base_bot_func_alias in base_bot_func_alias_list:
                        if base_bot_func_alias in func_link_order_list:
                            exists_flag = True
                    if exists_flag == True:
                        base_bot_func_addr = bot_func_addr
                        #print('bot:', hex(base_bot_func_addr), base_bot_func_alias_list)
            if base_top_func_addr != 0 and base_bot_func_addr != 0:
                top_func_name = functions[base_top_func_addr]['names'][0]
                bot_func_name = functions[base_bot_func_addr]['names'][0]
                #print('if :', top_func_name, bot_func_name, base_top_func_alias_list, base_bot_func_alias_list)
                link_order_top_func_index_list = \
                        _match_array_index_list(func_link_order_list, base_top_func_alias_list)
                link_order_bot_func_index_list = \
                        _match_array_index_list(func_link_order_list, base_bot_func_alias_list)
                #exit(-1)
                # check index
                if len(link_order_top_func_index_list) ==  len(link_order_bot_func_index_list) == 0:
                    continue
                for link_order_top_func_index in link_order_top_func_index_list:
                    for link_order_bot_func_index in link_order_bot_func_index_list:
                        hit_index_area_length = link_order_bot_func_index - link_order_top_func_index
                        # if 0 < hit_index_area_length <= MAX_AREA_LENGTH
                        if hit_index_area_length > 0 and hit_index_area_length <= MAX_AREA_LENGTH:
                            match_func_list += sorted(set(functions[multi_func_addr]['names']) & \
                                    set(func_link_order_list[link_order_top_func_index+1:link_order_bot_func_index]))


        if len(match_func_list) > 0 and len(functions[multi_func_addr]['names']) > len(match_func_list):
            #print('-')
            #print(func_link_order_list[link_order_top_func_index])
            # print('[matched : func link order] : 0x%x : %s -> %s ' % \
            #         (multi_func_addr, functions[multi_func_addr]['names'], match_func_list) \
            #         ) # dbg
            #print(func_link_order_list[link_order_bot_func_index])
            #functions[multi_func_addr]['names'] = match_func_list
            if multi_func_addr in matched_func_dict.keys():
                matched_func_dict[multi_func_addr] =  matched_func_dict[multi_func_addr] + match_func_list
            else:
                matched_func_dict[multi_func_addr] = match_func_list

    for addr, match_func_list in matched_func_dict.items():
        if len(functions[addr]['names']) > len(match_func_list):
            #print('matched! %s : %s -> %s ' % (hex(addr), functions[addr]['names'], match_func_list))
            functions[addr]['names'] = match_func_list
        matched_func_num = matched_func_num + 1
    #exit(-1)
    return functions, matched_func_num

def id_func_name_for_linkorder(functions, target_path, toolchain_path, alias_list, call_map, id_l_count, exclude_func_list):
    def get_func_list(functions, call_map):
        check_link_order_func_list = []
        libfunc_callee_addr_list = [] # library function call function address list
        userfunc_callee_addr_list = [] # library function call function address list
        func_addr_list = []
        for addr in functions.keys():
            func_addr_list.append(addr)
        func_addr_list = sorted(set(func_addr_list))
        # set first library function address
        for f_addr in func_addr_list:
            if len(TOP_LIBC_FUNC_LIST) == 0:
                if len(functions[f_addr]['names']) > 0 and functions[f_addr]['detected'] == True \
                        and len(set(functions[f_addr]['names']) & set(INITIAL_CRT_FUNCTIONS)) == 0 : # case of HEUL     ISTIC_FIRST_FUNCTION is empty
                    entry_libfunc_addr = f_addr
                    break
            elif len(set(functions[f_addr]['names']) & set(TOP_LIBC_FUNC_LIST)) > 0: # if the address of a l     ibrary function
                entry_libfunc_addr = f_addr
                break
            else:
                entry_libfunc_addr = 0
        # format call map
        fmt_call_map = []
        for call_map_index, _ in enumerate(call_map):
            fmt_call_map.append([call_map[call_map_index][0], call_map[call_map_index][2]])
        # get library function call library function address
        for call_inst_addr, callee_addr in fmt_call_map:
            #print(hex(call_inst_addr), hex(callee_addr))
            try:
                if entry_libfunc_addr <= call_inst_addr and functions[callee_addr]['detected'] == True:
                    #print(functions[callee_addr]['names'])
                    libfunc_callee_addr_list.append(callee_addr)
            except KeyError:
                continue
        # get user define function call library function address
        for call_inst_addr, callee_addr in fmt_call_map:
            try:
                if entry_libfunc_addr > call_inst_addr and functions[callee_addr]['detected'] == True:
                    #print(hex(call_inst_addr), '-', hex(callee_addr), ':', functions[callee_addr]['names'])
                    userfunc_callee_addr_list.append(callee_addr)
            except KeyError:
                continue
        # get not call library function address
        not_call_func_addr_list = \
                sorted(set(func_addr_list) - set(libfunc_callee_addr_list+userfunc_callee_addr_list))
        # check link order function address
        check_link_order_func_addr_list = sorted(set(userfunc_callee_addr_list + not_call_func_addr_list))
        # create check link order function list
        for check_link_order_func_addr in userfunc_callee_addr_list:
            for func in functions[check_link_order_func_addr]['names']:
                check_link_order_func_list.append(func)
        # all function
        all_func_list = []
        for addr in sorted(functions.keys()):
            for func in functions[addr]['names']:
                all_func_list.append(func)
        return check_link_order_func_list, all_func_list


    #func_list = sorted(sum( [v['names'] for v in functions.values()], []))
    use_func_list, all_func_list = get_func_list(functions, call_map)
    #print(len(use_func_list), len(all_func_list))
    #exit(-1)
    id_l_num = 0
    #print(func_list, toolchain_path, target_path.split('/')[-1])
    # link order path
    link_order_list_path = \
            STELFTOOLS_PATH + './_tmpdir/link_order_list/' \
            + target_path.split('/')[-1] + '_'  + str(id_l_count) + '.olist'
    # global link order path
    global_link_order_list_path = \
            STELFTOOLS_PATH + './_tmpdir/link_order_list/' \
            + target_path.split('/')[-1] + '_'  + str(id_l_count) + 'g.olist'
    # global link order path
    all_link_order_list_path = \
            STELFTOOLS_PATH + './_tmpdir/link_order_list/' \
            + target_path.split('/')[-1] + '_'  + str(id_l_count) + 'all.olist'
    # get real link order list
    check_func_list = sorted(set(use_func_list) - set(exclude_func_list))
    dummy_bin_name = target_path.split('/')[-1] + '.' + str(id_l_count)
    func_link_order_list, global_func_link_order_list, _exclude_func_list \
            = DubMaker.get_order_list(check_func_list, toolchain_path, dummy_bin_name)
    exclude_func_list += _exclude_func_list
    # save link order list
    with open(link_order_list_path, 'wt') as f:
        for func_link_order in func_link_order_list:
            f.write("%s\n" % func_link_order)
    # check
    while True:
        functions, mf_num = link_order_base_identificate(functions, alias_list, func_link_order_list)
        if mf_num == 0:
            break
        else:
            id_l_num += 1

    #print(len(exclude_func_list))
    # check only first
    if id_l_count == 0:
        while True:
            functions, mf_num = link_order_base_identificate(functions, alias_list, global_func_link_order_list)
            if mf_num == 0:
                break
        #aa
        check_all_func_list = sorted(set(all_func_list) - set(exclude_func_list))
        func_link_order_list, _, _ \
                = DubMaker.get_order_list(check_all_func_list, toolchain_path, dummy_bin_name)
        while True:
            functions, mf_num = link_order_base_identificate(functions, alias_list, func_link_order_list)
            if mf_num == 0:
                break
    return functions, id_l_num, func_link_order_list

def get_func_name_list_alias_list(multi_func_name_list, alias_list):
    func_name_alias_list = []
    for multi_func_name in multi_func_name_list:
        for alias in alias_list:
            if multi_func_name in alias:
                func_name_alias_list.extend(alias)
    if func_name_alias_list == []:
        func_name_alias_list = multi_func_name_list
    return sorted(set(func_name_alias_list))

def id_func_name_for_depend(functions, call_map, depend_path, alias_list):
    def get_depend_list(d_list_path):
        depend_data = []
        try:
            with open(d_list_path, 'r') as d_list:
                for d in d_list:
                    d = d.strip()
                    d = d.replace('\n', '')
                    d = d.split(' ')
                    alias = d[0].split(',')
                    d[0] = alias
                    depend_data.append(d)
        except FileNotFoundError:
            print('Dependency file not found : %s' % d_list_path, file=sys.stderr)
            exit(1)
        return depend_data

    def caller_base_name_filter(functions, call_map, depend_data, alias_list):
        matched_func_num = 0
        for key, value in functions.items():
            if value['detected'] == True and len(value['names']) == 1:
                for opecode_addr, inst_size, operand_callee_addr in call_map:
                    if int(key) <= int(opecode_addr) <= int(key)+int(functions[key]['size']):
                        for caller_alias, callee, offset in depend_data:
                            #print(caller_alias, callee, offset)
                            _caller_func_len = len(value['names'])
                            if len(set(value['names']) & set(caller_alias)) == _caller_func_len \
                                    or _caller_func_len == 1 and value['names'][0] == caller_alias[0]:
                                try:
                                    functions_callee = functions[operand_callee_addr]['names']
                                    #print('dbg :', functions[operand_callee_addr['names'])
                                except: # case of init function
                                    continue
                                call_offset_start = opecode_addr - key
                                call_offset_end = call_offset_start + inst_size
                                if call_offset_start <= int(offset) < call_offset_end:
                                    # get all callee alias
                                    functions_callee_aliases = get_func_name_list_alias_list(functions_callee, alias_list)
                                    #print(functions_callee, callee, functions_callee_aliases)
                                    #if callee in functions_callee and len(functions_callee) > 1:
                                    if callee in functions_callee_aliases and len(functions_callee) > 1:
                                        # print('[matched! : caller base] (%s) : %s => %s' % \
                                        #         ( \
                                        #         hex(operand_callee_addr), \
                                        #         functions[operand_callee_addr]['names'], \
                                        #         [callee] \
                                        #         )) # dbg
                                        functions[operand_callee_addr]['names'] = [callee]
                                        matched_func_num = matched_func_num + 1
        return functions, matched_func_num

    def callee_base_name_filter(functions, call_map, depend_data, alias_list):
        matched_func_num = 0
        # get multi funcname address
        multi_funcname_addr_list = []
        for f_addr, f_info in functions.items():
            if len(f_info['names']) > 1:
                try:
                    if f_info['size'] >= 0:
                        multi_funcname_addr_list.append(f_addr)
                        # print(hex(f_addr), f_info['names'], f_info['size'])
                except KeyError:
                    continue
        multi_funcname_addr_list = sorted(set(multi_funcname_addr_list))
        for multi_addr in multi_funcname_addr_list:
            # search depend function info
            candidate_func_depend_dict = {}
            for candidate_func in functions[multi_addr]['names']:
                #print(candidate_func)
                for d_caller_funcs, d_callee_func, d_offset in depend_data:
                    if candidate_func in d_caller_funcs:
                        #print('-')
                        #print(','.join(d_caller_funcs), d_callee_func, d_offset)
                        d_caller_alias_str = ','.join(d_caller_funcs)
                        #print(candidate_func, d_caller_funcs, ':', d_callee_func, d_offset)
                        if not d_caller_alias_str in candidate_func_depend_dict:
                            candidate_func_depend_dict[d_caller_alias_str] = { \
                                    'callees' : [[d_callee_func, d_offset]], \
                                    'func_num' : 1 } # initialize
                        elif [d_callee_func, d_offset] not in candidate_func_depend_dict[d_caller_alias_str]['callees']:
                            candidate_func_depend_dict[d_caller_alias_str]['callees'].append([d_callee_func, d_offset])
                            candidate_func_depend_dict[d_caller_alias_str]['func_num'] = \
                                    candidate_func_depend_dict[d_caller_alias_str]['func_num'] + 1
            #print('-----')
            #print(hex(multi_addr), functions[multi_addr])
            matched_func_list = []
            # check call
            for candidate_func in functions[multi_addr]['names']:
                compare_callee_num = 0
                offset_recode_list = [] # ToDo bad fix style
                for inst_addr, inst_size, callee_addr in call_map:
                    if multi_addr <= inst_addr < (multi_addr + int(functions[multi_addr]['size'])):
                        callee_inst_offset = inst_addr - multi_addr
                        for d_caller_alias_str, callee_info in candidate_func_depend_dict.items():
                            if candidate_func in d_caller_alias_str.split(','):
                                #print(hex(int(callee_addr, 16)), \
                                #        hex(multi_addr), hex(multi_addr + int(functions[multi_addr]['size'])))
                                try:
                                    #callee_func = functions[int(callee_addr, 16)]['names']
                                    callee_func = functions[callee_addr]['names']
                                    #print(candidate_func, callee_func)
                                except KeyError: # case of refere object (non function)
                                    continue
                                for callee in callee_info['callees']:
                                    #print(hex(multi_addr), candidate_func, ':', d_caller_alias_str, callee_func, callee)
                                    callee_func_alias_list = get_func_name_list_alias_list([callee[0]], alias_list)
                                    #print('-')
                                    #print(candidate_func, set(callee_func), set(callee_func_alias_list), \
                                    #         len(set(callee_func) & set(callee_func_alias_list)))
                                    #print(len(callee_func), len(callee_func_alias_list))
                                    _callee_func_len = len(callee_func)
                                    #print('co', callee_inst_offset, int(callee[1]), callee_inst_offset+inst_size)
                                    if len(set(callee_func) & set(callee_func_alias_list)) == _callee_func_len \
                                            and callee_inst_offset <= int(callee[1]) < callee_inst_offset+inst_size \
                                            or _callee_func_len == 1 and callee_func[0] == callee[0]:
                                        if not int(callee[1]) in offset_recode_list: # ToDo bad fix style
                                            offset_recode_list.append(int(callee[1]))
                                            compare_callee_num += 1
                                            #print(candidate_func, callee[0], '(', int(callee[1]), ')',  ':', compare_callee_num)
                                #print('cc',compare_callee_num, candidate_func_depend_dict[d_caller_alias_str]['func_num'])
                                if compare_callee_num == candidate_func_depend_dict[d_caller_alias_str]['func_num']:
                                    for matched_func in sorted(set([candidate_func]) & set(d_caller_alias_str.split(','))):
                                        if not matched_func in matched_func_list:
                                            #print('m :', matched_func)
                                            matched_func_list.append(matched_func)
            if len(matched_func_list):
                if len(functions[multi_addr]['names']) > len(matched_func_list):
                    matched_func_num += 1
                    if len(matched_func_list) > 1:
                        for alias in alias_list:
                            if len(matched_func_list) ==  len(set(matched_func_list) & set(alias)):
                                matched_func_list = [min(alias, key=len)]
                    #print('[matched! : callee base] (%s) : %s -> %s' % (hex(multi_addr), functions[multi_addr]['names'], matched_func_list))
                    functions[multi_addr]['names'] = matched_func_list
        return functions, matched_func_num

    id_d_num = 0
    depend_list = get_depend_list(depend_path)
    while True:
        functions, r_matched_func_num = caller_base_name_filter(functions, call_map, depend_list, alias_list)
        functions, e_matched_func_num = callee_base_name_filter(functions, call_map, depend_list, alias_list)
        if e_matched_func_num == r_matched_func_num == 0:
            break
        else:
            id_d_num += 1
    return functions, id_d_num

def multiple_consecutive_candidate_filt(functions, link_order_list, alias_list):
    #for l in link_order_list:
    #    print(l)
    #exit(-1)
    libfunc_addr_list = []
    multi_libfunc_addr_list = []
    for addr, funcs in functions.items():
        if funcs['detected'] == True:
            libfunc_addr_list.append(addr)
            if len(funcs['names']) > 1:
                multi_libfunc_addr_list.append(addr)
    libfunc_addr_list = sorted(libfunc_addr_list)
    multi_libfunc_addr_list = sorted(multi_libfunc_addr_list)

    consective_multi_funcname_addr_dict = {}
    for i in range(len(libfunc_addr_list)):
        if libfunc_addr_list[i] in multi_libfunc_addr_list:
            #print('---')
            s_multi_func_name_addr = libfunc_addr_list[i]
            #print('s', hex(libfunc_addr_list[i]), functions[libfunc_addr_list[i]]['names'])
            s_multi_func_name_alias_list = get_func_name_list_alias_list(functions[libfunc_addr_list[i]]['names'], alias_list)
            #print(s_multi_func_name_alias_list)
            for s_multi_func_name_alias in s_multi_func_name_alias_list:
                s_multi_func_name_alias_index_list = _match_array_index(link_order_list, s_multi_func_name_alias)
                for s_multi_func_name_alias_index in s_multi_func_name_alias_index_list:
                    # check
                    if len(set(functions[s_multi_func_name_addr]['names']) & set([link_order_list[s_multi_func_name_alias_index-1]])) \
                            or len(set(functions[s_multi_func_name_addr]['names']) & set([link_order_list[s_multi_func_name_alias_index-2]])):
                        continue
                    #print('-')
                    next_i = 0
                    consective_addr_list = []
                    while True:
                        if len(libfunc_addr_list) <= i+next_i:
                            break
                        candidate_func_name_list = functions[libfunc_addr_list[i+next_i]]['names']
                        candidate_func_name_alias_list = \
                                get_func_name_list_alias_list(candidate_func_name_list, alias_list)
                        #print(hex(libfunc_addr_list[i+next_i]), candidate_func_name_alias_list, '-', \
                        #        link_order_list[s_multi_func_name_alias_index+next_i], s_multi_func_name_alias_index+next_i)
                        if not link_order_list[s_multi_func_name_alias_index+next_i] in candidate_func_name_alias_list:
                            #print('b', link_order_list[s_multi_func_name_alias_index+next_i])
                            break
                        next_i+=1
                    if next_i >= 3:
                        for count_i in range(next_i):
                            if len(functions[libfunc_addr_list[i+count_i]]['names']) == 1:
                                continue
                            detect_fname = link_order_list[s_multi_func_name_alias_index+count_i]
                            for _alias in alias_list:
                                if detect_fname in _alias:
                                    detect_fname = min(_alias, key=len)
                            #print('[matched : additional func link order] (%s) %s -> %s' % ( \
                            #        hex(libfunc_addr_list[i+count_i]), \
                            #        functions[libfunc_addr_list[i+count_i]]['names'], \
                            #        detect_fname))
                            functions[libfunc_addr_list[i+count_i]]['names'] = [detect_fname]
    return functions


def arch_pattern_length(arch):
    length = 0
    if arch in ['aarch64']:
        length = 9
    elif arch in ['arm', \
            'armv4eb', 'armv4l', 'armv4tl', \
            'armv5-eabi', 'armv5l', \
            'armv6-eabihf', 'armv6l', \
            'armv7-eabihf', 'armv7l', 'armv7m' \
            ]:
        length = 4
    elif arch in ['x86', 'x86-i686', 'i386', 'i486', 'i586', 'i686', 'x86-core2', '80386']:
        length = 4
    elif arch in ['mips', 'mips32', 'mipsel', 'mips32el']:
        length = 9
    elif arch in ['mips64', 'mips64el']:
        length = 9
    elif arch in ['ppc', 'powerpc', 'powerpc-440fp', 'powerpc-e300c3', 'powerpc-e500mc']:
        length = 8
    elif arch in ['ppc64', 'powerpc64', 'powerpc64-e6500', 'powerpc64-pwoer8']:
        length = 16
    elif arch in ['risc-v', 'riscv', 'risc-v-32', 'risc-v-64']:
        length = 9
    elif arch in ['sparc', 'sparc64']:
        length = 9
    elif arch in ['x86_64', 'x86-64', 'x86-64-core-i7']:
        length = 8
    elif arch in ['arc']:
        length = 4
    elif arch in ['sh4']:
        length = 4
    elif arch in ['m68k', 'm68k-q800', 'm68k-mcf', 'm68k-mcf5208', 'm68000']:
        length = 4
    return length

def get_target_list(targets, lm_flag):
    if lm_flag == True:
        with open(targets[0], "rt") as f:
            target_list = f.readlines()
            target_list = [l.replace('\n', '') for l in target_list]
            return target_list
    else:
        return targets

def set_args():
    parser = argparse.ArgumentParser()
    # new
    parser.add_argument('-cfg', help = 'target path')
    parser.add_argument('-target', help = 'target path')
    # old
    parser.add_argument('--yara', help = 'yara rule path')
    parser.add_argument('--arch', help = 'yara rule path')
    #parser.add_argument('--pattern_length', '-pl', default = 8, type = int)
    parser.add_argument('--output_style', '-o', default='default', help = 'output style')
    parser.add_argument('--virtual_addr', '-va', action='store_true', help = 'output virtual address')
    parser.add_argument('--list_mode', '-lm', action='store_true', help = 'list mode')
    parser.add_argument('--alias_list', '-al', help = 'Enable function name identification by function dependency')
    parser.add_argument('--id_linkorder', '-id_l', help = 'Path to toolchain used to indentify function names by function link order')
    parser.add_argument('--id_depend', '-id_d', help = 'Enable function name identification by function dependency')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args = set_args()

    if os.path.exists(args.cfg) == True:
        cfg_info = {}
        with open(args.cfg) as cfg_fp:
            cfg_info = json.load(cfg_fp)
        # load config file
        target_path      = args.target
        target_arch      = cfg_info['arch']
        yara_path        = STELFTOOLS_PATH + cfg_info['yara_path']
        compiler_path    = cfg_info['compiler_path']
        alias_list_path  = STELFTOOLS_PATH + cfg_info['alias_list_path']
        depend_list_path = STELFTOOLS_PATH + cfg_info['dependency_list_path']
        # set flag
        alias_flag = False
        linkorder_flag = False
        depend_flag = False
        if os.path.exists(alias_list_path) == True:
            alias_flag = True
        if os.path.exists(compiler_path) == True:
            linkorder_flag = True
        if os.path.exists(depend_list_path) == True:
            depend_flag = True
    elif args.yara != None:
        target_path = args.target
        target_arch = args.arch
        yara_path = args.yara
        compiler_path = args.id_linkorder
        alias_list_path = args.alias_list
        depend_list_path = args.id_depend
    else:
      print("[ERROR] wrong argument")
      exit(-1)

    start_rule_length = arch_pattern_length(target_arch)

    target = get_target_fp(target_path) # target
    bin_target = target.read()
    # get symbol table information
    try:
        symtab_info = get_symtab_info_by_capstone(target_path) # get vaddr
    except exceptions.ELFParseError as e:
        symtab_info = get_symtab_info_by_reaelf(target_path) # get vaddr
    base_vaddr = symtab_info[0][2]
    # get function call information
    call_map, top_inst_addr, bot_inst_addr = get_func_addr(target, base_vaddr)
    # get target file size
    target_size = int(target.seek(0, os.SEEK_END))
    # do matching
    #print(start_rule_length)
    for _length in range(start_rule_length, 0, -1):
        yara_rules, risc_v_flag = get_yara_rule(yara_path, 'func', _length) # rule
        # matching
        _match_res = yara_matching(yara_rules, target) # do matching
        # format matching result
        _functions = format_match_res(_match_res, symtab_info, risc_v_flag)
        #print('---')
        #for _addr in sorted(_functions.keys()):
        #    print('dbg', _length, ':', hex(_addr), _functions[_addr])
        if _length == start_rule_length:
            #functions = marge_nomatch_functions(_functions, call_map, base_vaddr)
            functions = marge_nomatch_functions(_functions, call_map)
        else:
            functions = marge_functions(functions, _functions)
    # delete mismatch signature
    functions = del_mismatch(functions)
    # close target fp
    target.close()
    # function name identification
    # set function alias list
    alias_list = []
    if alias_flag == True:
        alias_list = get_alias_list(alias_list_path)
    # delete alias function name
    functions = del_alias(functions, alias_list)

    #identifying the function name
    id_loop_count = 0
    exclude_func_list = []
    # identifying the function name
    while True:
        # identifying the function name based on the link order
        id_l_num = 0
        if linkorder_flag == True:
            functions, id_l_num, link_order_list = id_func_name_for_linkorder(\
                    functions, target_path, compiler_path, \
                    alias_list, call_map, id_loop_count, exclude_func_list \
                    )
        # identifying the function name based on the dependency
        id_d_num = 0
        if depend_flag == True:
            functions, id_d_num = id_func_name_for_depend( \
                    functions, call_map, depend_list_path, alias_list \
                    )
        if id_l_num == id_d_num == 0:
            break
        id_loop_count += 1

    if linkorder_flag == True and alias_flag == True:
        functions = multiple_consecutive_candidate_filt(functions, link_order_list, alias_list)
    # save checked target dump info
    targets_info = {'name' : target_path, \
            'functions' : functions, \
            'size' : target_size, \
            'base_vaddr' : base_vaddr, \
            }
    output(targets_info, target_path, args.output_style) # output result
