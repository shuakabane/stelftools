#@category stelftools.Python
#!/usr/bin/env python3

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType

import os
import sys
import json
import time
import subprocess

STELFTOOLS_PATH="/home/akabane/research/en/stelftools/"

currentProgram = state.getCurrentProgram()
location = str(currentProgram.getExecutablePath())

def func_ident():
    # init
    _flat_api = FlatProgramAPI(currentProgram)
    _address_factory = currentProgram.getAddressFactory()
    # ask toolchain config path
    tc_cfg_path = askFile("FILE", "Select toolchain cfg file:")
    tc_cfg_path = str(tc_cfg_path)
    # set running command
    run_cmd = [ \
            "python3", STELFTOOLS_PATH + 'func_ident.py', \
            '-cfg', tc_cfg_path, \
            '-target', location, \
            '-o', 'ghidra']
    # run stelftools (func_ident.py)
    cmd_res = subprocess.check_output(run_cmd).split('\n')
    res_list = [x for x in cmd_res if x != '']
    for res in res_list:
        addr = int(res.split(':')[0], 16)
        funcname = res.split(':')[1]
        current_addr = _address_factory.getAddress(hex(addr))
        # If the identified address is not identified as a function by ghidra
        if _flat_api.getFunctionAt(current_addr) == None:
            createFunction(current_addr, None)
        # get current function name
        current_name = _flat_api.getFunctionAt(current_addr)
        # rename function name
        if current_name != funcname:
            print(current_addr, current_name, '->', funcname) # dbg
            current_name.setName(funcname, SourceType.USER_DEFINED)

def make_rules():
    # ask toolchain name
    tc_name = str(askString("String Specification", "1. Please type a toolchain name:"))
    # ask toolchain directory path
    tc_dir_path = str(askDirectory("DIR", "2. Select toolchain directory:"))
    # ask toolchain compiler path
    set_cp_YesOrNo = askYesNo("yes or no", "3. Do you want to specify a toolchain compiler?")
    tc_compiler_path = ""
    if set_cp_YesOrNo == True:
        tc_compiler_path = str(askFile("FILE", "3. Please select a compiler for the toolchain:"))
    # ask toolchain architecture
    tc_arch = str(askString("Arch", "4. Please type a toolchain architecture:"))
    # set running command
    run_cmd = [ \
            "python3", STELFTOOLS_PATH + 'libfunc_info_create.py', \
            '-name', tc_name, \
            '-tp', tc_dir_path, \
            '-cp', tc_compiler_path, \
            '-arch', tc_arch]
    # run stelftools (libfunc_info_create.py)
    cmd_res = subprocess.check_output(run_cmd).split('\n')
    res_list = [x for x in cmd_res if x != '']
    for res in res_list:
        print(res)

if __name__ == '__main__':
    # choise Identification of library functions or
    # Generate YARA rules and other rules used for matching
    stelftools_feat = askChoices("Choice", "Please choose stelftools feat.", \
            ["func_ident", "make_rules"])
    # Identification of library functions
    if stelftools_feat[0] == "func_ident":
        print('start stelftools : Identify library function name -->')
        start = time.time()
        func_ident()
        end = time.time()
        print("<-- finish stelftools %.2f seconds" % (end-start))
    # Generate YARA rules and other rules used for matching
    elif stelftools_feat[0] == "make_rules":
        print('start stelftools : Make rules, etc. -->')
        start = time.time()
        make_rules()
        end = time.time()
        print("<-- finish stelftools %.2f seconds" % (end-start))
