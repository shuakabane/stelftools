#! /usr/bin/env python3
#
# mkrule.py - yara rule generator
#
# Usage: ./mkrule.py archive_files
# - e.g., ./libfunc_mkrule.py /opt/cross-compilter/i586/lib/lib*.a
# - e.g., ./libfunc_mkrule.py $(find /opt/cross-compiler/i586/ -type f -name '*.[a|o]')
#
# Output: patterns.yara
#
# Requirements:
# - pyelftools: ELF file tools
# - capstone: disassembler
# - arpy
# Changes:
# - genptn.py -> mkrule.py -> libfunc_mkrule.py

import os
import re
import sys
import shutil
import struct
import arpy
#import ar
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import *
from elftools.elf.sections import SymbolTableSection
from capstone import *
import logging
import hashlib
import magic
import argparse

import cxxfilt
import collections

col, row = shutil.get_terminal_size()

# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level=logging.WARNING)
# logging.basicConfig(level=logging.INFO)

# Needed for c++ because function names are too long in C++
MAX_RULE_INDENTIFIER_LENGTH = 30
# Needed for c++ because there are too many same opecode functions
#MAX_ALIASES = 50 # TODO: C++ function names may cause too long string errors
MAX_ALIASES = 70 # TODO: C++ function names may cause too long string errors
#VERSION = '0.1.1_2020_04_26'
VERSION = '0.2.0_2021_07_29'
# MINIMUM_PATTERN_LENGTH = 6 # TODO: parameter tuning
MINIMUM_PATTERN_LENGTH = 0
#MAXIMUM_PATTERN_LENGTH = 1000 # 600  # TODO: parameter tuning
MAXIMUM_PATTERN_LENGTH = 15000 # 600  # TODO: risc-v

CRT_INIT_FINI_FUNC_LIST = ['.init', '_init', '__init', '.fini', '_fini', '__fini']

def fetch_opecodes(f, arfile = '', exapis = []):
    global MAXIMUM_PATTERN_LENGTH
    tab = {}
    crt_marge_tab = {}
    if hasattr(f, 'header'):
        fname = f.header.name.decode('utf-8')
    elif hasattr(f, 'name'):
        fname = f.name
    else:
        logging.error('Could not identify the file name')
        exit(-1)
    if len(arfile) > 0:
        arfile = '@' + arfile
    e = ELFFile(f)

    # create hex string based text code
    textsec = {}
    rodatasec = {}
    for sec in e.iter_sections():
        #print(sec.name, sec['sh_type'], (sec['sh_flags'] & SH_FLAGS.SHF_EXECINSTR), SH_FLAGS.SHF_EXECINSTR )
        #if sec.name in ['.opd']:
        #    print(sec, sec['sh_type'], (sec['sh_flags'] & SH_FLAGS.SHF_EXECINSTR) == SH_FLAGS.SHF_EXECINSTR )
        #    exit(-1)
        if (sec['sh_type'] == 'SHT_PROGBITS' and (sec['sh_flags'] & SH_FLAGS.SHF_EXECINSTR) == SH_FLAGS.SHF_EXECINSTR):
            # if not sec.name.startswith('.text'): continue
            logging.debug('%s: %s' % (fname, sec.name))
            # extract a .text section corresponding to this relocation table
            hexstr = ['%02X' % (x) for x in struct.unpack('B' * len(sec.data()), sec.data())]
            textsec[sec.name] = hexstr
        elif (sec['sh_type'] == 'SHT_PROGBITS' and sec['sh_flags'] == SH_FLAGS.SHF_ALLOC):
            # get alias
            alias_list = []
            if sec.name.startswith('.rodata.'):
                fmt_sec_name = sec.name[8:]
            elif sec.name.startswith('.rdata.'):
                fmt_sec_name = sec.name[7:]
            else:
                continue
            # check symtab
            symtab_info = []
            symtab_sec = e.get_section_by_name('.symtab')
            if isinstance(symtab_sec, SymbolTableSection):
                symbols = e.get_section(symtab_sec.header.sh_link)
                for st_index, sym in enumerate(symtab_sec.iter_symbols()):
                    st_value = sym['st_value'] # offset
                    st_size  = sym['st_size']
                    st_type  = sym['st_info']['type']
                    st_bind  = sym['st_info']['bind']
                    st_vis   =  sym['st_other']['visibility']
                    st_ndx   =  sym['st_shndx']
                    st_name  = sym.name

                    symtab_info.append([ \
                            st_index, st_value, st_size, st_type, st_bind, st_vis, st_ndx, st_name \
                            ])
            #for _, _, _, _, _, _, st_ndx, st_name in symtab_info:
            #    if st_name == fmt_sec_name:
            #        fmt_ndx = st_ndx
            #for _, _, _, st_type, _, _, st_ndx, st_name in symtab_info:
            #    if fmt_ndx == st_ndx and len(st_name) != 0 and st_type == 'STT_OBJECT':
            #        alias_list.append(st_name)
            for _, _, _, st_type, _, _, _, st_name in symtab_info:
                if st_type == 'STT_OBJECT' and len(st_name) != 0:
                    alias_list.append(st_name)

            #print(alias_list)
            hexstr = ['%02X' % (x) for x in struct.unpack('B' * len(sec.data()), sec.data())]
            rodatasec[','.join(sorted(alias_list))] = hexstr

    ## 1. text section : statically functions
    # analyze relocation sections
    relnames = ['.rel' + x for x in textsec.keys()]
    relnames += ['.rela' + x for x in textsec.keys()]
    #print(relnames)

    for sec in e.iter_sections():
        if not sec['sh_type'] in ['SHT_REL', 'SHT_RELA']:
            continue
        if not sec.name in relnames:
            continue
        logging.debug('%s: %s' % (fname, sec.name))

        # extract a .text section corresponding to this relocation table
        if sec.name.startswith('.rela'):
            name = sec.name[5:]
        elif sec.name.startswith('.rel'):
            name = sec.name[4:]
        else:
            logging.error('Unsupported section name: %s' % sec.name)
            exit(-1)

        # test: RISCV : prefetch reloc info
        # save relocation info
        _reloc_info = {}
        # checked r_offset
        _checked_r_offset = []
        for r in sec.iter_relocations():
            offset = r['r_offset']
            rtype = r['r_info_type']
            if not offset in _reloc_info.keys():
                _reloc_info[offset] = { 'rtype' : [rtype] }
            else:
                _marge_rtype = _reloc_info[offset]['rtype'] + [rtype]
                _reloc_info[offset]['rtype'] = _marge_rtype

        for r in sec.iter_relocations():
            offset = r['r_offset']
            rtype = r['r_info_type']
            #logging.warning('Not supported architecture: %s %s' % (e['e_machine'], e['e_ident']['EI_CLASS']))
            #exit(-1)
            if e['e_machine'] == 'EM_386' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':  # Intel 80386
                # R_386_32(1) and R_386_PC32(2)
                # R_386_TLS_GD(18), R_386_TLS_LE(0x11), R_386_TLS_LDO_32(0x20), R_386_TLS_LDM(0x13)
                # ref.) readelf --all tpp.os and perror.os
                if rtype in [0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x11, 0x12, 0x13, 0x20, 0x26, 0x2a]:
                    if rtype in [0x12] and textsec[name][offset - 3] == '8D' and  textsec[name][offset - 2] == '04' and textsec[name][offset - 1] == '1D':
                        textsec[name][offset-3:offset] = ['( ' + textsec[name][offset-3] + ' | 65 )', '( ' + textsec[name][offset-2] + ' | A1 )', '( ' + textsec[name][offset-1] + ' | 00 )']

                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                # R_386_TLS_IE(0x0F) R_386_TLS_GOTIE(0x10) R_386_GOT32X(0x2b)
                # ref) https://docs.oracle.com/cd/E19683-01/817-3677/chapter8-1/index.html
                elif rtype in [0x0f, 0x10, 0x2b]:
                    if textsec[name][offset - 1] == 'A1':
                        textsec[name][offset - 1:offset + 4] = ['( A1 | B? )', '??', '??', '??', '??'] # al-1.2.4-i586, centos-5.4-i386
                    elif textsec[name][offset - 2] == '8B':
                        textsec[name][offset - 2:offset + 4] = ['( 8B | C7 )', '??', '??', '??', '??', '??']
                    elif textsec[name][offset - 2] == '03': # 03 15 00 00 00 00: add reg, ds:[0x0] --> 81 C? 00 00 00 00: add reg, 0xffffff?? # centos-5.4-i586
                        textsec[name][offset - 2:offset + 4] = ['( 03 | 81 )', '??', '??', '??', '??', '??']
                    elif textsec[name][offset - 2] == '3B': # 3b 98 00 00 00 00: cmp reg, dword ptr [reg] --> 81 F? 00 00 00 00 # fflush+0x13: gcc-7.4.0-i686+uClibc-ng-1.0.30
                        textsec[name][offset - 2:offset + 4] = ['( 3B | 81 )', '??', '??', '??', '??', '??']
                    else:
                        #logging.warning('Unexpected opecode: %s %s type %x offset %x', textsec[name][offset - 2], textsec[name][offset - 1], rtype, offset)
                        continue
                        exit(-1)
                elif rtype in [20, 21]:  # R_386_16(20), R_386_PC16(21)
                    textsec[name][offset:offset + 2] = ['??', '??']
                else:
                    #logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    continue
                    # md = Cs(CS_ARCH_X86, CS_MODE_32)
                    # md.detail = True
                    # for i in md.disasm(text.data()[offset - 2:offset + 15], 0):
                    #     print('\t0x%x(%d): %s %s' % (i.address, i.size, i.mnemonic, i.op_str))
                    exit(-1)
            elif e['e_machine'] == 'EM_X86_64' and e['e_ident']['EI_CLASS'] == 'ELFCLASS64':  # Intel 80386
                # readelf -r /usr/lib/x86_64-linux-gnu/libc.a | cut -f3-4 -d' ' | grep R_ | cut -b10- | sort | uniq -c
                # TODO: what's size? 009 R_X86_64_GOTPCREL 016 R_X86_64_GOTTPOFF 02a R_X86_64_REX_GOTP
                # 001 R_X86_64_64 002 R_X86_64_PC32 004 R_X86_64_PLT32 009 R_X86_64_GOTPCREL
                # 00a R_X86_64_32 00b R_X86_64_32S 013 R_X86_64_TLSGD 014 R_X86_64_TLSLD 
                # 015 R_X86_64_DTPOFF32 016 R_X86_64_GOTTPOFF
                # 017 R_X86_64_TPOFF32 01a R_X86_64_GOTPC32 029 R_X86_64_GOTPCREL 02a R_X86_64_REX_GOTP
                R_X86_64_GOTTPOFF = 0x16
                R_X86_64_REX_GOTPCRELX = 0x2a
                if rtype in [0x01]:
                    textsec[name][offset:offset + 8] = ['??', '??', '??', '??', '??', '??', '??', '??']
                elif rtype in [0x02, 0x04, 0x09, 0x0A, 0x0B, 0x13, 0x14, 0x15, 0x17, 0x1A, 0x29]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [R_X86_64_GOTTPOFF, R_X86_64_REX_GOTPCRELX]:
                    textsec[name][offset-2:offset + 4] = ['??', '??', '??', '??', '??', '??']
                    #textsec[name][offset-3:offset-2] = ['( ' + textsec[name][offset-3] + ' | 4? )']
                    textsec[name][offset-3:offset-2] = ['4?']
                else:
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    #continue
                    # md = Cs(CS_ARCH_X86, CS_MODE_32)
                    # md.detail = True
                    # for i in md.disasm(text.data()[offset - 2:offset + 15], 0):
                    #     print('\t0x%x(%d): %s %s' % (i.address, i.size, i.mnemonic, i.op_str))
                    exit(-1)
            elif e['e_machine'] == 'EM_ARM' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                # Relocation types
                # 0x00 R_ARM_NONE, 0x01 R_ARM_PC24, 0x02 R_ARM_ABS32, 0x03 R_ARM_REL32, 0x04 R_ARM_LDR_PC_G0
                # 0x05 R_ARM_ABS16, 0x06 R_ARM_ABS12, 0x07 R_ARM_THM_ABS5, 0x08 R_ARM_ABS8, 0x09 R_ARM_SBREL32
                # 0x10 R_ARM_THM_CALL
                # 0x18 R_ARM_GOTOFF32, 0x19 R_ARM_GOTPC, 0x1a R_ARM_GOT32, 0x1b R_ARM_PLT32, 0x1c R_ARM_CALL
                # 0x1d R_ARM_JUMP24, 0x1c, 0x68 R_ARM_TLS_GD32, 0x6b R_ARM_TLS_IE32, 0x6c R_ARM_TLS_LE32
                if rtype in [0x00]:
                    None
                elif rtype in [0x08]:
                    textsec[name][offset:offset + 1] = ['??']
                elif rtype in [0x05]:
                    textsec[name][offset:offset + 2] = ['??', '??']
                #elif rtype in [0x06]:
                #    half_wild_hex = textsec[name][offset:offset + 2]
                #    textsec[name][offset:offset + 2] = ['??', half_wild_hex[1][0]+'?']
                #    print('check')
                #elif rtype in [0x07]:
                #    half_wild_hex = textsec[name][offset:offset + 2]
                #    textsec[name][offset:offset + 2] = ['?'+half_wild_hex[0][1], half_wild_hex[1][0]+'?']
                #    print('check')
                elif rtype in [0x01]:
                    textsec[name][offset:offset + 3] = ['??', '??', '??']
                elif rtype in [0x02, 0x03, 0x04, 0x09, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x68, 0x6b, 0x6c]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [0xa, 0x1e, 0x2b, 0x2c, 0x66, 0x69, 0x6a]: # additional
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [0x12b, 0x2d, 0x2e, 0x12b]: # additional
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                #elif rtype in [0x10]:
                #    half_wild_hex = textsec[name][offset:offset + 4]
                #    print('check')
                else:
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    exit(-1)
            elif e['e_machine'] == 'EM_AARCH64' and e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
                # Relocation types
                # 0x101 R_AARCH64_ABS64
                # 0x113 R_AARCH64_ADR_PREL_PG_HI21, 0x115 R_AARCH64_ADD_ABS_LO12_NC,
                # 0x116 R_AARCH64_LDST8_ABS_LO12_NC, 0x11A R_AARCH64_JUMP26, 0x11B R_AARCH64_CALL26,
                # 0x11C R_AARCH64_LDST16_ABS_LO12_NC, 0x11D R_AARCH64_LDST32_ABS_LO12_NC,
                # 0x11E R_AARCH64_LDST64_ABS_LO12_NC, 0x137 R_AARCH64_ADR_GOT_PAGE,
                # 0x138 R_AARCH64_LD64_GOT_LO12_NC, 0x139 R_AARCH64_LD64_GOTPAGE_LO15
                # 0x21D R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21,
                # 0x21E R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC, 0x225 R_AARCH64_TLSLE_ADD_TPREL_HI12
                # 0x227 R_AARCH64_TLSLE_ADD_TPREL_LO12_NC, 0x232 R_AARCH64_TLSDESC_ADR_PAGE21
                # 0x233 R_AARCH64_TLSDESC_LD64_LO12, 0x234 R_AARCH64_TLSDESC_ADD_LO12
                # 0x239 R_AARCH64_TLSDESC_CALL
                if rtype in [0x00]:
                    None
                elif rtype in [0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109, \
                        0x10a, 0x10b, 0x10c, 0x10d, 0x10e, 0x10f, 0x113, 0x115, 0x116, 0x118, 0x11a, 0x11b, 0x11c, 0x11d, 0x11e, \
                        0x137, 0x138, 0x139, 0x12b, 0x21d, 0x21e, 0x225, 0x227, 0x232, 0x233, 0x234, 0x239]:
                    textsec[name][offset:offset+4] = ['??', '??', '??', '??']
                else :
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    #continue
                    exit(-1)
            elif e['e_machine'] == 'EM_MIPS' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                # 0x01 R_MIPS_NONE 0x05 R_MIPS_HI16 0x06 R_MIPS_LO16, 0x09 R_MIPS_GOT16, 0x0A R_MIPS_PC16
                # 0x0c R_MIPS_GPREL32
                R_MIPS_GOT16 = 0x09
                R_MIPS_CALL16 = 0x0b
                R_MIPS_TLS_TPREL_HI16 = 0x31
                R_MIPS_TLS_TPREL_LO16 = 0x32

                if rtype in [0x00]:
                    None
                elif rtype in [0x05, 0x06, 0x0a, 0x2e, R_MIPS_TLS_TPREL_HI16, R_MIPS_TLS_TPREL_LO16]:
                    if e['e_ident']['EI_DATA'] == 'ELFDATA2MSB': # mips
                        textsec[name][offset+2:offset + 4] = ['??', '??']
                    if e['e_ident']['EI_DATA'] == 'ELFDATA2LSB': # mipsel
                        textsec[name][offset:offset + 2] = ['??', '??']
                elif rtype in [0x0c]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [0x04, 0x25, 0x2a, 0x2b, 0x2c, 0x2d]: # mips r3000
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [R_MIPS_GOT16, R_MIPS_CALL16]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                else:
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    exit(-1)
            elif e['e_machine'] == 'EM_MIPS' and e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
                # 0x00 R_MIPS_NONE
                # 0x07 R_MIPS_GPREL16, 0x0b R_MIPS_CALL16,
                # 0x13 R_MIPS_GOT_DISP, 0x14 R_MIPS_GOT_PAGE, 0x15 R_MIPS_GOT_OFST
                # 0x25 R_MIPS_JALR, 0x2e R_MIPS_TLS_GOTTPR
                if rtype in [0x00]:
                    None
                elif rtype in [0x07, 0x0b, 0x13, 0x14, 0x15, 0x2e, 0xa, 0x2a, 0x31, 0x32]:
                    if e['e_ident']['EI_DATA'] == 'ELFDATA2MSB': # mips
                        textsec[name][offset+2:offset + 4] = ['??', '??']
                    elif e['e_ident']['EI_DATA'] == 'ELFDATA2LSB': # mipsel
                        textsec[name][offset:offset + 2] = ['??', '??']
                elif rtype in [0x25, 0xc]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                else:
                    print('Not implemented: unknown relocation type (0x%X) at 0x%X in %s' % (rtype, offset, fname))
                    exit(-1)
            elif e['e_machine'] == 'EM_PPC' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                # 0x00 R_PPC_NONE, 0x04 R_PPC_ADDR16_LO, 0x06 R_PPC_ADDR_16_HA, 0x0a R_PPC_REL24, 0x0e R_PPC_GOT16
                # 0x12 R_PPC_PLTREL24, 0x17 R_PPC_LOCAL24PC, 0x1a R_PPC_REL32, 
                # 0x43 R_PPC_TLS, 0x57 R_PPC_GOT_TPREL16
                # 0xfa R_PPC_REL16_HI 0xfc R_PPC_REL16_HA
                R_PPC_TPREL16_LO = 0x46
                R_PPC_TPREL16_HA = 0x48
                R_PPC_GOT_TLSGD16 = 0x4f
                R_PPC_GOT_TPREL16 = 0x57
                R_PPC_TLSGD = 0x5f

                R_PPC_DTPREL16_LO = 0x4b
                R_PPC_DTPREL16_HA = 0x4d
                R_PPC_GOT_TLSLD16 = 0x53
                R_PPC_TLSLD = 0x60
                if rtype in [0x00]:
                    None
                elif rtype in [0x04, 0x06, 0x0e, 0xfa, 0xfc]:#, R_PPC_TPREL16_HA]:
                    textsec[name][offset:offset + 2] = ['??', '??']
                elif rtype in [R_PPC_GOT_TPREL16, R_PPC_GOT_TLSGD16, R_PPC_TPREL16_LO, R_PPC_TPREL16_HA]: # optimize?
                    textsec[name][offset-2:offset+2] = ['??', '??', '??', '??']
                elif rtype in [0x1a, 0x43, R_PPC_TLSGD]:
                    textsec[name][offset:offset + 4] = [ '??', '??', '??', '??']
                elif rtype in [0x0a, 0x12, 0x17]:
                    half_wild_hex = textsec[name][offset:offset + 4]
                    textsec[name][offset:offset + 4] = ['( '+half_wild_hex[0][0]+'? | 3? )', '??', '??', '??']
                elif rtype in [R_PPC_GOT_TLSLD16, R_PPC_DTPREL16_LO, R_PPC_DTPREL16_HA]:
                    textsec[name][offset:offset + 2] = ['??', '??']
                elif rtype in [R_PPC_TLSLD]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                else:
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    exit(-1)
            elif e['e_machine'] == 'EM_PPC64' and e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
                # ToDo : need many fix
                R_PPC64_NONE = 0x00
                R_PPC64_REL24 = 0x0a
                R_PPC64_REL14 = 0x0b
                R_PPC64_REL32 = 0x1a
                R_PPC64_TOC16_LO = 0x30
                R_PPC64_TOC16_HA = 0x32
                R_PPC64_TOC16_DS = 0x3f
                R_PPC64_TOC16_LO_DS = 0x40
                R_PPC64_TLS = 0x43
                R_PPC64_TPREL16_LO = 0x46
                R_PPC64_TPREL16_HA = 0x48
                R_PPC64_GOT_TLSGD16 = 0x4f
                R_PPC64_GOT_TPREL16_DS = 0x57
                R_PPC64_GOT_TPREL16_LO_DS = 0x58
                R_PPC64_GOT_TPREL16_HA = 0x5a
                R_PPC64_TLSGD = 0x6b
                R_PPC64_REL16_LO = 0xfa
                R_PPC64_REL16_HA = 0xfc
            
                fix_offset = (offset // 4) * 4
                if rtype in [R_PPC64_NONE]:
                    None
                elif rtype in [R_PPC64_TOC16_LO, R_PPC64_TOC16_HA, R_PPC64_TOC16_DS, R_PPC64_TOC16_LO_DS, \
                        R_PPC64_TPREL16_HA, R_PPC64_TPREL16_LO, R_PPC64_GOT_TPREL16_HA, R_PPC64_GOT_TPREL16_LO_DS, \
                        R_PPC64_GOT_TPREL16_DS, R_PPC64_GOT_TPREL16_DS, R_PPC64_GOT_TPREL16_DS, R_PPC64_GOT_TLSGD16, \
                        R_PPC64_REL16_LO, R_PPC64_REL16_HA]:
                    #textsec[name][fix_offset:fix_offset + 2] = ['??', '??']
                    textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
                elif rtype in [R_PPC64_REL14]:
                    #textsec[name][fix_offset+2:fix_offset + 4] = ['??', '??']
                    textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
                elif rtype in [R_PPC64_REL24]:
                    _0_7byte = textsec[name][fix_offset:fix_offset+1][0][0]
                    # 4? xx xx xx xx : bl instcuction
                    # 60 00 00 00 00 : nop
                    textsec[name][fix_offset:fix_offset + 4] = ['( 60 | ' + _0_7byte+'? )', '??', '??', '??']
                    textsec[name][fix_offset+4:fix_offset + 8] = ['??', '??', '??', '??']
                elif rtype in [R_PPC64_REL32, R_PPC64_TLS, R_PPC64_TLSGD]:
                    textsec[name][fix_offset:fix_offset + 4] = ['??', '??', '??', '??']
                else:
                    #print(textsec[name][fix_offset-2:fix_offset + 4])
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, fix_offset, fname)
                    exit(-1)
                    #continue
            elif e['e_machine'] == 'EM_SPARC' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':
                # 0x00 R_SPARC_NONE, 0x03 R_SPARC_32, 0x07 R_SPARC_WDISP30, 0x08 R_SPARC_WDISP22, 0x09 R_SPARC_HI22
                # 0x0b R_SPARC_13, 0x0c R_SPARC_LO10, 0x0d R_SPARC_GOT10, 0x0e R_SPARC_GOT13, 0x0f R_SPARC_GOT22
                # 0x10 R_SPARC_PC10, 0x11 R_SPARC_PC22, 0x12 R_SPARC_WPLT30,
                # 0x38 R_SPARC_TLS_GD_HI22, 0x39 R_SPARC_TLS_GD_LO10, 0x3a R_SPARC_TLS_GD_ADD, 0x3b R_SPARC_TLS_GD_CALL
                # 0x43 R_SPARC_TLS_IE_HI22, 0x44 R_SPARC_TLS_IE_LO10, 0x45 R_SPARC_TLS_IE_LD
                R_SPARC_TLS_GD_HI22 = 0x38
                R_SPARC_TLS_GD_LO10 = 0x39
                R_SPARC_TLS_GD_ADD = 0x3a
                R_SPARC_TLS_GD_CALL = 0x3b

                R_SPARC_TLS_IE_HI22 = 0x43
                R_SPARC_TLS_IE_LO10 = 0x44
                R_SPARC_TLS_IE_LD = 0x45

                R_SPARC_GOTDATA_OP_HIX22 = 0x52
                R_SPARC_GOTDATA_OP_LOX22 = 0x53
                R_SPARC_GOTDATA_OP = 0x54
                if rtype in [0x00]:
                    None
                #elif rtype in [R_SPARC_GOTDATA_OP_LOX22]:
                #    half_wild_hex = textsec[name][offset+2]
                #    textsec[name][offset+2:offset + 4] = [ half_wild_hex[0]+'?', '??']
                elif rtype in [0x0b, 0x0e, 0x12]:
                    #textsec[name][offset+2:offset + 4] = ['??', '??']
                    textsec[name][offset:offset + 4] = [ '??', '??', '??', '??']
                elif rtype in [0x0c, 0x0d, 0x10]:
                    half_wild_hex = textsec[name][offset+2:offset + 4]
                    textsec[name][offset+2:offset + 4] = [ half_wild_hex[0][0]+'?', '??']
                elif rtype in [0x08, 0x09, 0x0f, 0x11, \
                        R_SPARC_TLS_GD_HI22, R_SPARC_TLS_GD_LO10, R_SPARC_TLS_GD_ADD, R_SPARC_TLS_GD_ADD]:#, R_SPARC_GOTDATA_OP_HIX22]:
                    textsec[name][offset+1:offset + 4] = ['??', '??', '??']
                elif rtype in [0x03, 0x07, 0x3b]:
                    if rtype in [0x07]:
                        if textsec[name][offset+0] == '40' and textsec[name][offset+4] == '9E':
                            textsec[name][offset+4:offset+8] = ['( ' + textsec[name][offset+4] + ' | 01 )', '( ' + textsec[name][offset+5] + ' | 00 )', '( ' + textsec[name][offset+6] + ' | 00 )', '( ' + textsec[name][offset+7] + ' | 00 )']
                    textsec[name][offset:offset + 4] = [ '??', '??', '??', '??']
                elif rtype in [R_SPARC_TLS_IE_HI22, R_SPARC_TLS_IE_LO10, R_SPARC_TLS_IE_LD, \
                        R_SPARC_GOTDATA_OP, R_SPARC_GOTDATA_OP_HIX22, R_SPARC_GOTDATA_OP_LOX22]:
                    textsec[name][offset:offset + 4] = [ '??', '??', '??', '??']
                else:
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    #continue
                    exit(-1)
            elif e['e_machine'] == 'EM_SPARCV9' and e['e_ident']['EI_CLASS'] == 'ELFCLASS64':
                fix_rtype = rtype & 0xff
                # 0x00 R_SPARC_NONE, 0x03 R_SPARC_32, 0x07 R_SPARC_WDISP30, 0x08 R_SPARC_WDISP22, 0x09 R_SPARC_HI22
                # 0x0b R_SPARC_13, 0x0c R_SPARC_LO10, 0x0d R_SPARC_GOT10, 0x0e R_SPARC_GOT13, 0x0f R_SPARC_GOT22
                # 0x10 R_SPARC_PC10, 0x11 R_SPARC_PC22, 0x12 R_SPARC_WPLT30,
                # 0x38 R_SPARC_TLS_GD_HI22, 0x39 R_SPARC_TLS_GD_LO10, 0x3a R_SPARC_TLS_GD_ADD, 0x3b R_SPARC_TLS_GD_CALL
                # 0x43 R_SPARC_TLS_IE_HI22, 0x44 R_SPARC_TLS_IE_LO10, 0x45 R_SPARC_TLS_IE_LD

                R_SPARC_OLO10 = 0x21
                R_SPARC_HH22  = 0x22
                R_SPARC_HM10  = 0x23
                R_SPARC_LM22  = 0x24

                R_SPARC_TLS_GD_HI22 = 0x38
                R_SPARC_TLS_GD_LO10 = 0x39
                R_SPARC_TLS_GD_ADD = 0x3a
                R_SPARC_TLS_GD_CALL = 0x3b

                R_SPARC_TLS_IE_HI22 = 0x43
                R_SPARC_TLS_IE_LO10 = 0x44
                R_SPARC_TLS_IE_LD = 0x45

                R_SPARC_TLS_IE_LDX = 0x46
                R_SPARC_TLS_IE_ADD = 0x47
                R_SPARC_TLS_LE_HIX22 = 0x48
                R_SPARC_TLS_LE_LOX10 = 0x49

                R_SPARC_GOTDATA_OP_HIX22 = 0x52
                R_SPARC_GOTDATA_OP_LOX22 = 0x53
                R_SPARC_GOTDATA_OP = 0x54
                if fix_rtype in [0x00]:
                    None
                #elif fix_rtype in [R_SPARC_GOTDATA_OP_LOX22]:
                #    half_wild_hex = textsec[name][offset+2]
                #    textsec[name][offset+2:offset + 4] = [ half_wild_hex[0]+'?', '??']
                elif fix_rtype in [0x0b, 0x0e, 0x12]:
                    #textsec[name][offset+2:offset + 4] = ['??', '??']
                    textsec[name][offset:offset + 4] = [ '??', '??', '??', '??']
                elif fix_rtype in [0x0c, 0x0d, 0x10]:
                    half_wild_hex = textsec[name][offset+2:offset + 4]
                    textsec[name][offset+2:offset + 4] = [ half_wild_hex[0][0]+'?', '??']
                elif fix_rtype in [0x08, 0x09, 0x0f, 0x11, \
                        R_SPARC_TLS_GD_HI22, R_SPARC_TLS_GD_LO10, R_SPARC_TLS_GD_ADD, R_SPARC_TLS_GD_ADD]:#, R_SPARC_GOTDATA_OP_HIX22]:
                    textsec[name][offset+1:offset + 4] = ['??', '??', '??']
                elif fix_rtype in [0x03, 0x07, 0x3b]:
                    if fix_rtype in [0x07]:
                        if textsec[name][offset+0] == '40' and textsec[name][offset+4] == '9E':
                            textsec[name][offset+4:offset+8] = ['( ' + textsec[name][offset+4] + ' | 01 )', '( ' + textsec[name][offset+5] + ' | 00 )', '( ' + textsec[name][offset+6] + ' | 00 )', '( ' + textsec[name][offset+7] + ' | 00 )']
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif fix_rtype in [R_SPARC_TLS_IE_HI22, R_SPARC_TLS_IE_LO10, R_SPARC_TLS_IE_LD, \
                        R_SPARC_GOTDATA_OP, R_SPARC_GOTDATA_OP_HIX22, R_SPARC_GOTDATA_OP_LOX22]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif fix_rtype in [R_SPARC_OLO10, R_SPARC_HM10, R_SPARC_TLS_LE_LOX10]:
                    textsec[name][offset+2:offset+4] = ['??', '??']
                elif fix_rtype in [R_SPARC_HH22, R_SPARC_LM22, R_SPARC_TLS_LE_HIX22]:
                    textsec[name][offset+1:offset+4] = ['??', '??', '??']
                elif fix_rtype in [R_SPARC_TLS_IE_LDX, R_SPARC_TLS_IE_ADD]: # ?
                    textsec[name][offset:offset+4] = ['??', '??', '??', '??']
                else:
                    #logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', fix_rtype, offset, fname)
                    #continue
                    exit(-1)
            elif e['e_machine'] == 'EM_68K' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32': # Motorola
                # 0x00 R_68K_NONE, 0x01 R_68K_32, 0x04 R_68K_PC32, 0x07 R_68K_GOT32, 0x0a R_68K_GOT320,
                # 0x0b R_68K_GOT160, 0x0d R_68K_PLT32
                if rtype in [0x00]:
                    None
                elif rtype in [0x01, 0x04, 0x07, 0x0a, 0x0d]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [0x0b]:
                    textsec[name][offset:offset + 2] = ['??', '??']
                else:
                    #logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    continue
                    exit(-1)
            elif e['e_machine'] == 'EM_SH' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32': # Renesas
                # 0x00 R_SH_NONE, 0x01 R_SH_DIR32, 0x02 R_SH_REL32, 0xa0 R_SH_GOT32, 0xa1 R_SH_PLT32,
                # 0xa6 R_SH_GOTOFF, 0xa7 R_SH_GOTPC
                if rtype in [0x00]:
                    None
                elif rtype in [0x01, 0x02, 0x93, 0xa0, 0xa1, 0xa6, 0xa7]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                else:
                    logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    #continue
                    exit(-1)
            elif e['e_machine'] in ['EM_ARC_COMPACT', 'EM_ARC_COMPACT2'] and e['e_ident']['EI_CLASS'] == 'ELFCLASS32': # ARC
                # 0x00 R_ARC_NONE, 0x10 R_ARC_S25H_PCREL, 0x11 R_ARC_S25W_PCREL, 0x1b R_ARC_32_ME
                # 0x33 R_ARC_GOTPC32, 0x32 R_ARC_PC32, 0x3d R_ARC_S25H_PCREL_, 0x43 R_ARC_TLS_DTPOFF
                # 0x45 R_ARC_TLS_GD_GOT, 0x46 R_ARC_TLS_GD_LD, 0x48 R_ARC_TLS_IE_GOT, 0x4C R_ARC_S25W_PCREL
                if rtype in [0x00]:
                    None
                elif rtype in [0x10]:
                    #textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                    if textsec[name][offset-1] == '00':
                        textsec[name][offset:offset + 4] = ['( ?' + textsec[name][offset][1] + ' | DD | 45 )', '??', '??', '??']
                    else:
                        textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [0x11, 0x1b, 0x32, 0x33, 0x3d, 0x43, 0x45, 0x46, 0x48, 0x4c]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                elif rtype in [0x0e, 0x0f, 0x13, 0x15, 0x18, 0x1e, 0x30]:
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                else:
                    #logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    #continue
                    exit(-1)
            elif e['e_machine'] == 'EM_RISCV':# and e['e_ident']['EI_CLASS'] == 'ELFCLASS32': # RISC-V 32
                #print('this is risc-v 32bit')
                R_RISCV_BRANCH         = 0x10
                R_RISCV_JAL            = 0x11
                R_RISCV_CALL           = 0x12
                R_RISCV_CALL_PLT       = 0x13
                R_RISCV_GOT_HI20       = 0x14
                R_RISCV_TLS_GOT_HI20   = 0x15
                R_RISCV_TLS_GD_HI20    = 0x16
                R_RISCV_PCREL_HI20     = 0x17
                R_RISCV_PCREL_LO12_I   = 0x18
                R_RISCV_PCREL_LO12_S   = 0x19
                R_RISCV_HI20           = 0x1a
                R_RISCV_LO12_I         = 0x1b
                R_RISCV_LO12_S         = 0x1c
                R_RISCV_TPREL_HI20     = 0x1d
                R_RISCV_TPREL_LO12_I   = 0x1e
                R_RISCV_TPREL_LO12_S   = 0x1f
                R_RISCV_TPREL_ADD      = 0x20
                R_RISCV_ADD8           = 0x21
                R_RISCV_ADD16          = 0x22
                R_RISCV_ADD32          = 0x23
                R_RISCV_ADD64          = 0x24
                R_RISCV_SUB8           = 0x25
                R_RISCV_SUB16          = 0x26
                R_RISCV_SUB32          = 0x27
                R_RISCV_SUB64          = 0x28
                R_RISCV_GNU_VTINHERIT  = 0x29
                R_RISCV_GNU_VTENTRY    = 0x2a
                R_RISCV_ALIGN          = 0x2b
                R_RISCV_RVC_BRANCH     = 0x2c
                R_RISCV_RVC_JUMP       = 0x2d
                R_RISCV_LUI            = 0x2e
                R_RISCV_GPREL_I        = 0x2f
                R_RISCV_GPREL_S        = 0x30
                R_RISCV_TPREL_I        = 0x31
                R_RISCV_TPREL_S        = 0x32
                R_RISCV_RELAX          = 0x33
                R_RISCV_SUB6           = 0x34
                R_RISCV_SET6           = 0x35
                R_RISCV_SET8           = 0x36
                R_RISCV_SET16          = 0x37
                R_RISCV_SET32          = 0x38
                R_RISCV_32_PCREL       = 0x39


                #print('-')
                if not offset in _checked_r_offset \
                        and len(_reloc_info[offset]['rtype']) != 1 and R_RISCV_RELAX in _reloc_info[offset]['rtype']:
                    # check the size of the relaxation area
                    relax_size = 4
                    #print('base :', hex(offset), _reloc_info[offset])
                    while offset + relax_size in _reloc_info.keys() and R_RISCV_RELAX in _reloc_info[offset+relax_size]['rtype']:
                        #print('next -> :', hex(offset+relax_size), _reloc_info[offset+relax_size], R_RISCV_RELAX)
                        relax_size += 4
                    #print(hex(offset), relax_size)
                    #print(textsec[name][offset+4:offset+relax_size+4])
                    # case : 1
                    if relax_size == 4 \
                            and textsec[name][offset+relax_size:offset+relax_size+4] == ['E7', '80', '00', '00']:
                        relax_size += 4
                    # case : 2
                    if textsec[name][offset+4:offset+relax_size+4] == ['67', '00', '03', '00']:
                        textsec[name][offset+4:offset+8] = ['', '', '', '']
                        textsec[name][offset] = '[0-' + str(relax_size) + ']'
                        #textsec[name][offset] = '[0-' + str(relax_size-1) + ']'
                        #print(textsec[name][offset+4:offset+8])
                    else:
                        textsec[name][offset] = '[0-' + str(relax_size) + ']'
                    for _i in range(1, relax_size):
                        textsec[name][offset+_i] = ''
                    #print(textsec[name][offset:offset+relax_size], len(textsec[name][offset:offset+relax_size]))
                    # save checked r_offset to prevent reprocessing
                    for _c_offset in range(0, relax_size, 4):
                        _checked_r_offset.append(offset+_c_offset)

                #if False: # ToDo
                if offset in _checked_r_offset:
                    continue
                elif rtype in [R_RISCV_BRANCH]:
                    continue
                elif not rtype in [R_RISCV_RELAX]: # ToDo
                    textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
                else:
                    #logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
                    logging.warning('Not implemented: unknown relocation type %d - 0x%X at 0x%X in %s', rtype, rtype, offset, fname)
                    continue
                    exit(-1)
            #elif e['e_machine'] == 'EM_RISCV' and e['e_ident']['EI_CLASS'] == 'ELFCLASS64': # RISC-V 64
            #    #print('this is risc-v 64bit')
            #     if True: # ToDo
            #         textsec[name][offset:offset + 4] = ['??', '??', '??', '??']
            #     else:
            #         logging.warning('Not implemented: unknown relocation type (0x%X) at 0x%X in %s', rtype, offset, fname)
            #         exit(-1)
            else:
                # TODO: supports other architectures
                # https://docs.oracle.com/cd/E26924_01/html/E25909/chapter6-54839.html
                logging.warning('Not supported architecture: %s %s' % (e['e_machine'], e['e_ident']['EI_CLASS']))
                #continue
                exit(-1)

    #print(textsec)
    #print(textsec.keys())
    for _sym_name in textsec.keys():
        if _sym_name in CRT_INIT_FINI_FUNC_LIST:
            if fname.split('/')[-1] in ['crti.o', 'crtn.o']:
                opecodes_str = ' '.join(textsec[_sym_name])
                t_fname = fname.split('/')[-1]
                if t_fname in crt_marge_tab.keys():
                    crt_marge_tab[t_fname] = crt_marge_tab[t_fname] + [{'name': _sym_name, 'type': 'func', \
                            'size': len(textsec[_sym_name]), 'exports': [], 'imports': [], 'opecodes': opecodes_str}]
                else:
                    crt_marge_tab[t_fname] = [{'name': _sym_name, 'type': 'func', \
                            'size': len(textsec[_sym_name]), 'exports': [], 'imports': [], 'opecodes': opecodes_str}]

    if e['e_type'] == 'ET_DYN':
        symtab = e.get_section_by_name('.dynsym')
    else:
        symtab = e.get_section_by_name('.symtab')
    if symtab is None:
        return tab, crt_marge_tab
    exsymtab = {}

    # ToDo fix wong code
    opd_func_dict = {}
    _ndx_list = []
    _syminfo_list = []

    # check .opd flag
    opd_flag = False
    if e['e_machine'] == 'EM_PPC64':
        for sec in e.iter_sections():
            if sec.name == '.opd':
                opd_flag = True
                break
    if opd_flag == True:
        for sym in symtab.iter_symbols():
            #print(sym.name, sym.entry)
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_info']['bind'] == 'STB_LOCAL' \
                    and sym['st_size'] == 0:
                _ndx_list.append(sym['st_shndx'])
                _syminfo_list.append([sym['st_shndx'], sym.name, sym['st_value'], sym['st_size']])
            if sym['st_info']['type'] == 'STT_FUNC' and sym['st_info']['bind'] == 'STB_GLOBAL':
            #if sym['st_info']['type'] == 'STT_FUNC' and sym['st_info']['bind'] == 'STB_GLOBAL' \
            #        and sym.entry['st_other']['visibility'] == 'STV_HIDDEN':
                #print(sym['st_shndx'], [sym['st_shndx'], sym.name, sym['st_value'], sym['st_size']])
                _ndx_list.append(sym['st_shndx'])
                _syminfo_list.append([sym['st_shndx'], sym.name, sym['st_value'], sym['st_size']])

        # if the function instruction is actually in .text instead of .opd
        opd_func_info = {}
        for ndx in collections.Counter(_ndx_list).keys():
            _target_sec = e.get_section(ndx)
            #print(ndx, _target_sec.name)
            if _target_sec.name == '.opd':
                for sym in symtab.iter_symbols():
                    if len(sym.name) > 0 and sym['st_info']['type'] == 'STT_FUNC' \
                            and sym['st_other']['visibility'] in ['STV_DEFAULT', 'STV_HIDDEN'] \
                            and sym['st_shndx'] != 'SHN_UNDEF':
                        #print(sym.name, sym.entry)
                        opd_func_info[sym.name] = sym.entry
        ## get func order in sec
        f_order_in_sec = {}
        for k, v in opd_func_info.items():
            if not ndx in f_order_in_sec.keys():
                f_order_in_sec[v['st_shndx']] = [v['st_value']]
            else:
                f_order_in_sec[v['st_shndx']] = [v['st_value']] + f_order_in_sec[v['st_shndx']]
        for ndx in f_order_in_sec.keys():
            ndx_func_offset = 0
            #print(sorted(set(f_order_in_sec[ndx])))
            for ndx_in_val in sorted(set(f_order_in_sec[ndx])):
            #for ndx_in_val in [0x00, 0x30, 0x48, 0x60, 0x78]:
                #print(hex(ndx_in_val))
                for sym_name, sym_entry in opd_func_info.items():
                    if sym_entry['st_shndx'] == ndx and sym_entry['st_value'] == ndx_in_val:
                        if sym_name == 'free_mem':
                            continue
                        # print('-')
                        # print('base :', hex(ndx_func_offset))
                        if ndx_func_offset == 0:
                            _func_offset = ndx_func_offset
                        else:
                            _mod = (ndx_func_offset % 16)
                            # print(_mod)
                            if _mod == 0:
                                _func_offset = ndx_func_offset
                            else:
                                _func_offset = (ndx_func_offset // 16) * 16 + 16
                        #print(sym_name, sym_entry)
                        # print(hex(ndx_in_val), sym_name, hex(_func_offset), '-', hex(_func_offset + sym_entry['st_size']), \
                        #         len(textsec['.text'][_func_offset:_func_offset+sym_entry['st_size']]) )
                        # print(textsec['.text'][_func_offset : _func_offset+sym_entry['st_size']])
                        #print(textsec['.text'][_func_offset+sym_entry['st_size']-12 : _func_offset+sym_entry['st_size']])
                                #textsec['.text'][_func_offset:_func_offset+sym_entry['st_size']])
                        func_opecode = textsec['.text'][_func_offset:_func_offset+sym_entry['st_size']]
                        func_size = len(func_opecode)
                        opd_func_dict[sym_name] = {'func_opecode' : func_opecode, 'func_size' :func_size }
                        #ndx_func_offset += sym_entry['st_size']
                        ndx_func_offset = _func_offset + sym_entry['st_size']

    if e['e_machine'] == 'EM_RISCV':
        for t_sec, t_opecode_list in textsec.items():
            _offset_size = int(len(t_opecode_list) / 4)
            for _offset in range(_offset_size):
                _fmt_offset = _offset * 4
                if textsec[t_sec][_fmt_offset] == '63': # bnez instruction
                    textsec[t_sec][_fmt_offset:_fmt_offset+4] = ['?3', '??', '??', '??']
                elif textsec[t_sec][_fmt_offset] == 'E3': # bgeu instruction
                    textsec[t_sec][_fmt_offset:_fmt_offset+4] = ['?3', '??', '??', '??']
                elif textsec[t_sec][_fmt_offset:_fmt_offset+4] == ['E7', '80', '00', '00']: # bgeu instruction
                    textsec[t_sec][_fmt_offset:_fmt_offset+4] = ['E?', '??', '??', '??']
                elif textsec[t_sec][_fmt_offset:_fmt_offset+4] == ['67', '00', '03', '00']: # bgeu instruction
                    textsec[t_sec][_fmt_offset:_fmt_offset+4] = ['67', '??', '??', '??']

    # dbg
    exclude_alias_list = []
    f_info_dict = {}
    _offset_list = []
    _offset_idx = 0
    for sym in symtab.iter_symbols():
        if sym.name == '':
            continue
        #print('-')
        if sym['st_info']['type'] == "STT_FUNC":
            #print("%s: 0x%X %d %s " % ( sym.name, sym['st_value'], sym['st_size'], sym['st_shndx']) )
            _offset_list.append(sym['st_value'])
            for _f_key, _f_value in f_info_dict.items():
                if _f_value == {'value':sym['st_value'], 'size':sym['st_size'], 'st_shndx':sym['st_shndx']}:
                    exclude_alias_list.append(max([_f_key, sym.name], key=len))
            f_info_dict[sym.name] = {'value':sym['st_value'], 'size':sym['st_size'], 'st_shndx':sym['st_shndx']}
    _offset_list = sorted(set(_offset_list))

    # ppc64 custom
    if opd_flag == False:
        for sym in symtab.iter_symbols():
            if sym.name in exclude_alias_list: # exclude long alias
                #print(sym.name)
                continue
            if sym.name in exapis:
                continue
            if e['e_machine'] == 'EM_RISCV' and sym.name in ['_nl_locale_subfreeres', '__libc_freeres_fn']:
                continue
            if sym['st_info']['bind'] == 'STB_LOCAL':
                pass #continu
            if sym['st_info']['type'] == 'STT_NOTYPE' and sym['st_shndx'] == 'SHN_UNDEF' and len(sym.name) != 0:
                exsymtab[sym.name] = 'imports'
                continue
            if sym['st_info']['type'] != 'STT_FUNC':
                continue
            if sym['st_shndx'] == 'SHN_UNDEF':
                exsymtab[sym.name] = 'imports'
                continue
            else:
                exsymtab[sym.name] = 'exports'
            # if sym['st_other']['visibility'] == 'STV_HIDDEN': continue
            logging.debug('\t%s: offset = %d, size = %d' % (sym.name, sym['st_value'], sym['st_size']))

            # ToDo fix bug
            # arm glibc
            try:
                e.get_section(sym['st_shndx']).name
            except TypeError:
                continue
            target_sec = e.get_section(sym['st_shndx'])
            fix_sec_flag = False
            if e['e_machine'] == 'EM_PPC64':
                #print('-')
                #print(sym.name, sym.entry['st_value'])
                #print(sym.entry)
                # support ppc64 .opd section case  ## ToDo fix bad process
                #print(target_sec.name, textsec.keys(), sym.name) # dbg
                if not target_sec.name in textsec.keys() \
                        and target_sec.name in ['.opd']:
                    if '.text' in textsec.keys():

                        if len(textsec['.text']) != 0 and sym.entry['st_value'] == 0:# and len(textsec['.text.unlikely']) == 0:
                            target_sec = e.get_section_by_name('.text')
                        elif '.text.unlikely' in textsec.keys() \
                                and len(textsec['.text.unlikely']) != 0 and len(textsec['.text.unlikely']) != 0:
                            target_sec = e.get_section_by_name('.text.unlikely')
                            fix_sec_flag = True
                        else:
                            for _sec_name in textsec.keys():
                                if re.match(sym.name, _sec_name):
                                    target_sec = e.get_section_by_name(_sec_name)
                            if target_sec.name == '.opd' and '.text.unlikely' in textsec.keys():
                                if len(textsec['.text.unlikely']) != 0:
                                    target_sec = e.get_section_by_name('.text.unlikely')
                        if target_sec.name == '.opd': # force overwrite
                            target_sec = e.get_section_by_name('.text')
            #target_sec = e.get_section_by_name('.text.unlikely') # ppc64 .opd <-> .text support

            # check sec
            if not target_sec.name in textsec.keys():
                logging.error('error: %s was not found (%s)' % (target_sec.name, sym.name))
                exit(-1)  # continue #exit(-1)
            baseaddr = target_sec.header['sh_addr']

            # because there are functions whose size is set to zero, but its size is not zero.
            #print(target_sec.name, sym.name, sym['st_value'], textsec[target_sec.name])
            if sym['st_size'] == 0:
                # TODO: check valid length of the function
                _offset_idx += 1
                try:
                    _top = sym['st_value'] - baseaddr
                    _bot = _offset_list[_offset_idx]
                    #print('a', _top, _bot)
                except IndexError:
                    _top = sym['st_value'] - baseaddr
                    _bot = _top + len(textsec[target_sec.name][sym['st_value'] - baseaddr: ])
                    #print('b', _top, _bot)
                opecodes = textsec[target_sec.name][_top:_bot]
                size = len(opecodes)
            else:
                #print(sym['st_value'], baseaddr)
                #print('fix_sec_flag :', fix_sec_flag)
                if fix_sec_flag == False:
                    opecodes = textsec[target_sec.name][sym['st_value'] - baseaddr:sym['st_value'] + sym['st_size'] - baseaddr]
                    size = sym['st_size']
                else:
                    opecodes = textsec[target_sec.name][baseaddr:sym['st_size'] - baseaddr]
                    size = sym['st_size']
            #if e['e_machine'] in ['EM_386', 'EM_X86_64']:
            #    opecodes[0] = '( CC | %s )' % opecodes[0] # matches INT3 prologue for api hooking # TODO: sohuld modify functions code of crt*.o?

            # ELF executable # TODO: supports other architectures
            if e.header['e_type'] == 'ET_EXEC':
                if e['e_machine'] == 'EM_386' and e['e_ident']['EI_CLASS'] == 'ELFCLASS32':  # Intel 80386
                    md = Cs(CS_ARCH_X86, CS_MODE_32)
                    md.detail = True
                    code = target_sec.data()[sym['st_value'] - baseaddr:sym['st_value'] + sym['st_size'] - baseaddr]
                    index = 0
                    for i in md.disasm(code, 0):
                        if i.mnemonic == 'call' or i.mnemonic[0] == 'j':
                            if i.disp_offset > 0:
                                # print("%s %s (%s)" % (i.mnemonic, i.op_str, " ".join(["%02X" % (x) for x in i.bytes])))
                                opecodes[index + i.disp_offset:index + len(i.bytes)] = ['??'] * (len(i.bytes) - i.disp_offset)
                                # print("%s" % (' '.join(opecodes[index - len(i.bytes):index])))
                            elif i.imm_offset > 0:
                                opecodes[index + i.imm_offset:index + len(i.bytes)] = ['??'] * (len(i.bytes) - i.imm_offset)
                        else:
                            # but, use wildcards if the instruction has a 4-bytes displayment
                            if i.disp_offset > 0 and (len(i.bytes) - i.disp_offset) == 4:
                                opecodes[index + i.disp_offset:index + len(i.bytes)] = ['??'] * (len(i.bytes) - i.disp_offset)
                        index += len(i.bytes)
                else:
                    # TODO: supports other architectures
                    #logging.warning('Not supported architecture (disassemble): %s %s' % (e['e_machine'], e['e_ident']['EI_CLASS']))
                    continue
                    exit(-1)

            # get risc-v minimum legth
            opecode_minimum_length = 0
            if e['e_machine'] == 'EM_RISCV':
                #opecode_default_length = len(opecodes)
                _hex_num = len([_hex for _hex in opecodes if re.search('^[0-9a-fA-f]{2}$', _hex) != None or _hex == '??'])
                #_relax_num = len([_hex for _hex in opecodes if _hex.startswith('[')])
                opecode_minimum_length = _hex_num# + _relax_num * 4
                #print(opecode_default_length, opecode_minimum_length)



            if size > MAXIMUM_PATTERN_LENGTH:
                opecodes = opecodes[:MAXIMUM_PATTERN_LENGTH]

            # dbg : RISCVa
            if len(opecodes) != 0:
                # optimize
                #for _io in range(0, len(opecodes), 4):
                #    if opecodes[_io:_io+4] == ['67', '00', '03', '00']:
                #        opecodes[_io:_io+4] = ['??', '??', '??', '??']
                # relax
                if opecodes[0].startswith('['):
                    _fix_len = int(opecodes[0].split(']')[0].split('-')[1]) - 1
                    opecodes[0] = '??'
                    opecodes[1] = '[3-' + str(_fix_len) + ']'
                if opecodes[-1] == '':
                    target_flex_offset = 0
                    for _offset, _hex in enumerate(reversed(opecodes)):
                        if _hex.endswith(']'):
                            target_flex_offset = len(opecodes) - _offset -1
                            break
                    _fix_max_len = int(opecodes[target_flex_offset].split(']')[0].split('-')[1]) - 1
                    #_fix_min_len = int(opecodes[target_flex_offset].split(']')[0].split('-')[0].split('[')[1]) - 1
                    #opecodes[target_flex_offset] = '[' + str(_fix_min_len) + '-' + str(_fix_max_len) + ']'
                    opecodes[target_flex_offset] = '[' + str(0) + '-' + str(_fix_max_len) + ']'
                    opecodes[target_flex_offset+1] = '??'
            opecodes_str = ' '.join(opecodes)
            try:
                if sym.name == cxxfilt.demangle(sym.name):
                    #print(fname, sym.name)
                    if sym.name in CRT_INIT_FINI_FUNC_LIST:
                        continue
                    if opecode_minimum_length == 0:
                        if opecodes_str in tab.keys():
                            tab[opecodes_str].append({'name': sym.name, 'type': 'func', \
                                    'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile})
                        else:
                            tab[opecodes_str] = [{'name': sym.name, 'type': 'func', \
                                    'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile}]
                    else:
                        if opecodes_str in tab.keys():
                            tab[opecodes_str].append({'name': sym.name, 'type': 'func', \
                                    'size': size, 'min_size': opecode_minimum_length, \
                                    'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile})
                        else:
                            tab[opecodes_str] = [{'name': sym.name, 'type': 'func', \
                                    'size': size, 'min_size': opecode_minimum_length, \
                                    'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile}]
            except cxxfilt.InvalidName:
                continue
        for opecodes_str in tab.keys():
            for i in range(len(tab[opecodes_str])):
                for symname, export_or_import in exsymtab.items():
                    tab[opecodes_str][i][export_or_import].append(symname)
    # ppc64 custom
    if opd_flag == True:
        for func_name, func_info in opd_func_dict.items():
            #print(func_name, func_info)
            if func_info != 'checked':
                opecodes = func_info['func_opecode']
                size = func_info['func_size']
                # LIMIT LENGTH
                if size > MAXIMUM_PATTERN_LENGTH:
                    opecodes = opecodes[:MAXIMUM_PATTERN_LENGTH]
                opecodes_str = ' '.join(opecodes)
                try:
                    if func_name == cxxfilt.demangle(func_name):
                        #print(fname, func_name)
                        if opecodes_str in tab.keys():
                            tab[opecodes_str].append({'name': func_name, 'type': 'func', \
                                    'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile})
                        else:
                            tab[opecodes_str] = [{'name': func_name, 'type': 'func', \
                                    'size': size, 'exports': [], 'imports': [], 'objname': fname.split('/')[-1] + arfile}]
                except cxxfilt.InvalidName:
                    continue
                opd_func_dict[func_name] = 'checked'

    return tab, crt_marge_tab

def merge_dicts(src, dst):
    for key in src.keys():
        if key in dst.keys():
            dst[key] += src[key]
        else:
            dst[key] = src[key]
    return dst


def fetch_opecodes_from_arfile(arfile):
    tab = {}
    crt_tab = {}
    rel_arfile = arfile.split('/')[-1]
    arfile = os.path.abspath(arfile)
    objfiles = arpy.Archive(arfile)
    #print(objfiles)
    #for f in objfiles:
    #    print(f)
    #exit(1)
    for f in objfiles:
        # ToDo investigate the cause of the error
        fname = f.header.name.decode('utf-8')
        if fname in ['aeabi_sighandlers.os', 'aeabi_sighandlers.o']:
            continue
        #print('\x1b[2K\033[%d;1H%s' % (row, f.header.name.decode('utf-8')), end='', flush=True)
        newtab, new_crt_tab = fetch_opecodes(f, arfile = rel_arfile)
        tab = merge_dicts(tab, newtab)
        crt_tab = merge_dicts(crt_tab, new_crt_tab)
    #print('\x1b[2K\033[%d;1H' % row, end='', flush=True)
    return tab, crt_tab

def create_rule(syms, hexstr_opecodes, options = []):
    # rule = 'rule %s {\n' % funcs[-1]
    # TODO: rule name
    global MAX_RULE_INDENTIFIER_LENGTH
    global MAX_ALIASES
    funcs = sorted(set([syminfo['name'] for syminfo in syms])) # TODO: keep an order of names
    objnames = set([syminfo['objname'].replace('.o', '').replace('-', '_') for syminfo in syms])
    exports = set([(syminfo['objname'].split('.')[0].replace('-', '_'), ', '.join(syminfo['exports'])) for syminfo in syms])
    imports = set([(syminfo['objname'].split('.')[0].replace('-', '_'), ', '.join(syminfo['imports'])) for syminfo in syms])
    rule = 'rule %s {\n' % (funcs[-1][:MAX_RULE_INDENTIFIER_LENGTH].replace('.', '_DOT_').replace('@', '_AT_').replace('$', '_DOLLER_') + '_' + hashlib.md5(hexstr_opecodes.encode('utf-8')).hexdigest())
    #rule = 'rule %s {\n' % (min(funcs, key=len).replace('.', '_DOT_').replace('@', '_AT_').replace('$', '_DOLLER_') + '_' + hashlib.md5(hexstr_opecodes.encode('utf-8')).hexdigest())
    rule += '\tmeta:\n'
    #rule += '\t\taliases = "%s"\n' % ', '.join(funcs)
    rule += '\t\taliases = "%s"\n' % ', '.join(funcs[:MAX_ALIASES])
    rule += '\t\ttype = "%s"\n' % (syms[0]['type'])
    # if 'min_size' in syms[0].keys():
    #     rule += '\t\tsize = "%d"//\t\tmin_size = "%d"\n' % (syms[0]['size'], syms[0]['min_size'])
    # else:
    #     rule += '\t\tsize = "%d"\n' % (syms[0]['size'])
    rule += '\t\tsize = "%d"\n' % (syms[0]['size'])
    if 'objfiles' in options:
        rule += '\t\tobjfiles = "%s"\n' % ', '.join(list(objnames)[:5])
    if 'exports' in options:
        for objname, syms in exports:
            rule += '\t\texports_%s = "%s"\n' % (objname, syms)
    if 'imports' in options:
        for objname, syms in imports:
            rule += '\t\timports_%s = "%s"\n' % (objname, syms)
    if 'prototype' in options:
        rule += '\t\tprototype = "%s, %s"\n' % ('void', 'void')
    rule += '\tstrings:\n'
    rule += '\t\t$pattern = { %s }\n' % (hexstr_opecodes)
    rule += '\tcondition:\n'
    rule += '\t\t$pattern\n'
    rule += '}\n'
    return rule

def get_rules(tab):

    global VERSION
    rules_list = []
    rule_ver = '// YARA rules, version ' + VERSION + '\n\n'
    rules_list.append(rule_ver)
    #print('// YARA rules, version %s\n\n' % (VERSION))
    #f.write('// YARA rules, version %s\n\n' % (VERSION))
    for opecodes in sorted(tab.keys()):
        # TODO: remove wildcards (acc decreased in the evaluation of al-1.4.4 because of false positives: functions of size 5)

        question_mark_size = tab[opecodes][0]['size'] - opecodes.count('??')
        zero_hex_size = tab[opecodes][0]['size'] - opecodes.count('00')
        # if tab[opecodes][0]['size'] <= MINIMUM_PATTERN_LENGTH:
        if question_mark_size + zero_hex_size <= MINIMUM_PATTERN_LENGTH:
            #logging.warning('Skipped %s (%s)' % (', '.join(set([x['name'] for x in tab[opecodes]])),opecodes))
            continue
        opecode_list = opecodes.split(' ')
        wildcard_num = opecode_list.count('??')
        zero_hex_num = opecode_list.count('00')
        if len(opecodes.split(' ')) >= 1 and not opecode_list == [''] \
                and not wildcard_num == len(opecode_list) \
                and not zero_hex_num == len(opecode_list):
            rules = create_rule(tab[opecodes], opecodes, ['objfiles'])
            rules_list.extend(rules.split('\n'))
        #print(rules)
        #print(rules.split('\n'))
        #f.write(rules)
        #logging.info(rules)
    return rules_list

def output_function_names(fname, funcslist):
    uniqfunc = set()
    for funcs in funcslist:
        for func in funcs:
            uniqfunc.add(func)
    with open(fname, 'w') as f:
        for func in sorted(uniqfunc):
            #f.write(func + '\n')
            continue

def output_rules(rules_list, output_path):
    with open(output_path, 'w') as f:
        for rule in rules_list:
            f.write("%s\n" % rule)
    #print('Completed successfully ->', output_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument('--version', '-v', action = 'version', version = '%s %s' % (sys.argv[0], VERSION))
    parser.add_argument('--excluded-api', type = str, help = 'File name of a list that includes api names to be excluded')
    parser.add_argument('--save-api', type = str, help = 'File name of an api list')
    #parser.add_argument('--yara', '-y', default = 'patterns.yara', help = 'YARA file name to be saved')
    parser.add_argument('--min', '-m', default = 0, type = int, help = 'Minimum size of a function')
    parser.add_argument('--output_path', '-o', help = 'YARA file name to be saved')

    parser.add_argument('files', nargs = '+', help = 'File names of archive, object, executable files')
    args = parser.parse_args()
    MINIMUM_PATTERN_LENGTH = args.min

    logging.info('Analyzing archive files...')
    tab = {}
    crt_tab = {}

    EXCLUDE_OBJ_FILES = []#['Scrt1.o', 'rcrt1.o', 'crtbegin.o', 'crtbeginS.o', 'crtendS.o']

    for filename in args.files:
        # skip dynamic link object
        if filename.split('/')[-1] in EXCLUDE_OBJ_FILES:
            #print(filename.split('/')[-1])
            continue
        # c-lang only fast mode
        #skip c++ objfile (libstdc++)
        cpp_obj_list = ['libstdc++.a']
        if filename.split('/')[-1] in cpp_obj_list:
            continue

        #print('%s' % filename, flush=True)
        ftype = magic.from_file(filename, mime = True)

        if ftype == 'application/x-archive': #filename[-2:] == '.a':
            newtab, new_crt_tab = fetch_opecodes_from_arfile(filename)
        elif ftype == 'application/x-object': #filename[-2:] == '.o':
            with open(filename, 'rb') as f:
                newtab, new_crt_tab = fetch_opecodes(f)
        elif ftype in ['application/x-executable', 'application/x-sharedlib', 'application/x-pie-executable']: # TODO: support other executables
            if args.excluded_api and os.path.exists(args.excluded_api):
                with open(args.excluded_api, 'r') as f:
                    exapis = f.read().split('\n')
            else:
                exapis = []
            with open(filename, 'rb') as f:
                newtab, new_crt_tab = fetch_opecodes(f, exapis)
        elif ftype in ['text/plain', 'inode/symlink']:
            continue
        else:
            logging.error('Not supported file type of %s: %s' % (filename, ftype))
            #continue
            exit(-1)
        tab = merge_dicts(tab, newtab)
        crt_tab = merge_dicts(crt_tab, new_crt_tab)

    # marge crt opecode
    _tmp_crt_info = {}
    crt_obj_list = ['crti.o', 'crtn.o']
    if len(set(crt_tab.keys()) & set(crt_obj_list)) == len(crt_obj_list):
        crt_func_name_list = []
        # get connect crt function name list
        for info_in_obj in crt_tab['crti.o']:
            crt_func_name_list.append(info_in_obj['name'])

        for crt_obj,  crt_info_list in crt_tab.items():
            if crt_obj == 'crti.o':
                for crt_info in crt_info_list:
                    for crt_func_name in crt_func_name_list:
                        if crt_info['name'] == crt_func_name:
                            opecodes_str = crt_info['opecodes']
                            _tmp_crt_info[crt_func_name] = {'i-opecode' : opecodes_str}
        for crt_obj,  crt_info_list in crt_tab.items():
            if crt_obj == 'crtn.o':
                for crt_info in crt_info_list:
                    for crt_func_name in crt_func_name_list:
                        if crt_info['name'] == crt_func_name:
                            opecodes_str = crt_info['opecodes']
                            _tmp_crt_info[crt_func_name]['n-opecode'] = opecodes_str
        # marge
        marged_crt_func_opecs = {}
        for func_name in _tmp_crt_info.keys():
            for t_opecodes_str in _tmp_crt_info[func_name].values():
                if not func_name in marged_crt_func_opecs.keys():
                    marged_crt_func_opecs[func_name] = t_opecodes_str
                else:
                    marged_crt_func_opecs[func_name] = marged_crt_func_opecs[func_name] + ' [0-12] ' +  t_opecodes_str

        for _crt_func_name, _crt_func_opecodes in marged_crt_func_opecs.items():
            if _crt_func_opecodes in tab.keys():
                tab[_crt_func_opecodes] = [ \
                        tab[_crt_func_opecodes][0], \
                        { 'name': _crt_func_name, 'type': 'func', \
                        'size': len(_crt_func_opecodes.split(' ')), 'exports': [], 'imports': [], \
                        'objname': 'crti.o'} \
                        ]
            else:
                tab[_crt_func_opecodes] = [{'name': _crt_func_name, 'type': 'func', \
                        'size': len(_crt_func_opecodes.split(' ')), 'exports': [], 'imports': [], \
                        'objname': 'crti.o'}]

    # show shinked functions
    for v in tab.values():
        if v[0]['size'] > MAXIMUM_PATTERN_LENGTH:
            #logging.warning('Shrinked %s: %d -> %d' % (v[0]['name'], v[0]['size'], MAXIMUM_PATTERN_LENGTH))
            continue

    logging.info('\n\nGenerating a yara file...\n\n')
    rules_list = get_rules(tab)

    # output yara rule
    if args.output_path == 'no': # no output
        None
    elif args.output_path: # file output
        output_rules(rules_list, args.output_path)
    else: # stdout
        for rules in rules_list:
            print(rules)

    #if args.save_api:
    #    output_function_names(args.save_api, tab.values())
    #print('Completed successfully.')

