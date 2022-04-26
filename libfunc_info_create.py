#!/usr/bin/python3

import os
import re
import shutil
import struct
import sys
import hashlib
import logging
import collections
import glob
import argparse
import arpy
import cxxfilt
import magic
from capstone import *
from elftools.elf.constants import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import libfunc_mkrule # make lib func rule script
import libfunc_deparse # parse lib func dependency script

STELFTOOLS_PATH="/path/to/stelftools/"

MINIMUM_PATTERN_LENGTH = 0
MAXIMUM_PATTERN_LENGTH=15000

def create_toolchain_cfg_file(tc_name, arch, yara_rule_path, tc_compiler_path, alias_list_path, depend_list_path):
    yara_rule_path = yara_rule_path[len(STELFTOOLS_PATH):]
    alias_list_path = alias_list_path[len(STELFTOOLS_PATH):]
    depend_list_path = depend_list_path[len(STELFTOOLS_PATH):]
    with open(STELFTOOLS_PATH + "/toolchain_config/" + tc_name + ".json", "wt") as f:
        f.write("{\n")
        f.write("  \"name\" : \"" + tc_name + "\",\n")
        f.write("  \"arch\" : \"" + arch + "\",\n")
        f.write("  \"yara_path\" : \"" + yara_rule_path + "\",\n")
        f.write("  \"compiler_path\" : \"" + tc_compiler_path + "\",\n")
        f.write("  \"alias_list_path\" : \"" + alias_list_path + "\",\n")
        f.write("  \"dependency_list_path\" : \"" + depend_list_path + "\"\n")
        f.write("}\n")

def get_static_lib_file_list(tc_path):
    static_lib_file_list = \
            [obj_file for obj_file in glob.glob(tc_path+'/**', recursive=True) \
            if os.path.isfile(obj_file) and ( \
            obj_file.endswith('.a') \
            or obj_file.endswith('.o') \
            or obj_file.endswith('.os') \
            or obj_file.endswith('.lo') \
            )]
    #for static_lib_file in static_lib_file_list:
    #    print(static_lib_file)
    return static_lib_file_list

## mkrule
def mkrule(tc_path, tc_name):
    archive_list = []
    object_list = []
    rule_output_path = STELFTOOLS_PATH + "yara-patterns/" + tc_name + ".yara"

    static_lib_file_list = get_static_lib_file_list(tc_path)

    logging.info('Analyzing archive files...')
    tab = {}
    crt_tab = {}

    EXCLUDE_OBJ_FILES = ['Scrt1.o', 'rcrt1.o', 'crtbegin.o', 'crtbeginS.o', 'crtendS.o']

    for filename in static_lib_file_list:
        # skip dynamic link object
        if filename.split('/')[-1] in EXCLUDE_OBJ_FILES:
            #print(filename.split('/')[-1])
            continue

        #print('%s' % filename, flush=True)
        try:
            ftype = magic.from_file(filename, mime = True)
            if ftype == 'application/x-archive': #filename[-2:] == '.a':
                newtab, new_crt_tab = libfunc_mkrule.fetch_opecodes_from_arfile(filename)
            elif ftype == 'application/x-object': #filename[-2:] == '.o':
                with open(filename, 'rb') as f:
                    newtab, new_crt_tab = libfunc_mkrule.fetch_opecodes(f)
            elif ftype in ['application/x-executable', 'application/x-sharedlib', 'application/x-pie-executable']: # TODO: support other executables
                exapis = []
                with open(filename, 'rb') as f:
                    newtab, new_crt_tab = libfunc_mkrule.fetch_opecodes(f, exapis)
            elif ftype in ['text/plain', 'inode/symlink']:
                continue
            else:
                logging.error('Not supported file type of %s: %s' % (filename, ftype))
                #continue
                exit(-1)
        except magic.MagicException:
            continue
        tab = libfunc_mkrule.merge_dicts(tab, newtab)
        crt_tab = libfunc_mkrule.merge_dicts(crt_tab, new_crt_tab)

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
    rules_list = libfunc_mkrule.get_rules(tab)
    # output yara rule
    libfunc_mkrule.output_rules(rules_list, rule_output_path)
    return rule_output_path

def mkother(tc_path, tc_name):
    # create depend list
    depend_list_output_path = STELFTOOLS_PATH + "_tmpdir/dlists/" + tc_name + ".dlist"
    alias_list_output_path = STELFTOOLS_PATH + "_tmpdir/alias_list/" + tc_name + ".alist"

    static_lib_file_list = get_static_lib_file_list(tc_path)
    # make depend_list
    depend_list = {}
    for filename in static_lib_file_list:
        #print(filename) # debug
        try:
            ftype = magic.from_file(filename, mime = True)
            if ftype == 'application/x-object': # .o file
                with open(filename, 'rb') as f:
                    fname =  filename.split('/')[-1]
                    depend_list.update(libfunc_deparse.func_depend_analy(f, fname))
            elif ftype == 'application/x-archive': # .a file
                objfiles = libfunc_deparse.fetch_object_arfile(filename)
                for f in objfiles:
                    fname = f.header.name.decode('utf-8')
                    depend_list.update(libfunc_deparse.func_depend_analy(f, fname))
        except magic.MagicException:
            continue
    formatted_depend_data = libfunc_deparse.fmt_depend_data(depend_list)
    # output depend list
    libfunc_deparse.output_dlist(formatted_depend_data, depend_list_output_path)
    # output alias list
    libfunc_deparse.output_alist(formatted_depend_data, alias_list_output_path)
    return depend_list_output_path, alias_list_output_path

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument('-name', help = 'Toolchain name')
    parser.add_argument('--compiler_path', '-cp', help = 'Toolchain compiler path')
    parser.add_argument('-arch', help = 'arch')
    args = parser.parse_args()

    tc_name = args.name
    tc_path = "/".join(args.compiler_path.split('/')[0:(len(args.compiler_path.split('/'))-2)])
    tc_compiler_path = args.compiler_path
    arch = args.arch

    yara_rule_path = mkrule(tc_path, tc_name)
    depend_list_path, alias_list_path = mkother(tc_path, tc_name)

    create_toolchain_cfg_file( \
            tc_name, \
            arch, \
            yara_rule_path, \
            tc_compiler_path, \
            alias_list_path, \
            depend_list_path \
            )
