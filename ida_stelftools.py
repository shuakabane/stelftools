#! /usr/bin/env python3

import idc
import idaapi
import idautils
import ida_nalt
from shims import ida_shims

import os
import time
import json

from func_ident import *
from libfunc_info_create import *

def overwrite_func_label(match_info):
    same_name_idx = 0
    FUNC_LIB = 0x00000004
    for ea, f_info in match_info.items():
        if ida_shims.set_name(ea, f_info['names']):
            ida_shims.set_func_flags(ea, FUNC_LIB)
        else:
            same_name_idx += 1
            ida_shims.set_name(ea, f_info['names'] + '_' + str(same_name_idx))
            ida_shims.set_func_flags(ea, FUNC_LIB)

def arch_pattern_length(arch):
    length = 0
    if arch in ['aarch64']:
        length = 9
    elif arch in ['arm']:
        length = 8
    elif arch in ['x86', 'i386', 'i486', 'i586', 'i686']:
        length = 8
    elif arch in ['mips', 'mips32', 'mipsel', 'mips32el']:
        length = 9
    elif arch in ['mips64', 'mips64el']:
        length = 9
    elif arch in ['ppc']:
        length = 8
    elif arch in ['ppc64']:
        length = 16
    elif arch in ['risc-v-32', 'risc-v-64']:
        length = 9
    elif arch in ['sparc', 'sparc64']:
        length = 9
    elif arch in ['x86_64']:
        length = 8
    return length

def func_ident(tc_cfg_path):
    tc_cfg_info = {}
    with open(tc_cfg_path) as cfg_fp:
        tc_cfg_info = json.load(cfg_fp)

    # load config file
    target_path      = ida_nalt.get_input_file_path()
    target_arch      = tc_cfg_info['arch']
    yara_path        = STELFTOOLS_PATH + tc_cfg_info['yara_path']
    compiler_path    = tc_cfg_info['compiler_path']
    alias_list_path  = STELFTOOLS_PATH + tc_cfg_info['alias_list_path']
    depend_list_path = STELFTOOLS_PATH + tc_cfg_info['dependency_list_path']

    alias_list_flag = False
    linkorder_flag = False
    depend_flag = False

    if os.path.exists(alias_list_path) == True:
        alias_flag = True
    if os.path.exists(compiler_path) == True:
        link_order_flag = True
    if os.path.exists(depend_list_path) == True:
        dependency_flag = True

    print("delete alias :", alias_flag)
    print("function name identification by link order :", link_order_flag)
    print("function name identification by dependency :", dependency_flag)

    start_rule_length = arch_pattern_length(target_arch)

    target = get_target_fp(target_path) # target
    bin_target = target.read()
    # get symbol table information
    symtab_info = get_symtab_info(target_path) # get vaddr
    base_vaddr = symtab_info[0][2]
    # get function call information
    call_map, top_inst_addr, bot_inst_addr  = get_func_addr(target, base_vaddr)
    # get target file size
    target_size = int(target.seek(0, os.SEEK_END))
    # do matching
    for _length in range(start_rule_length, 0, -1):
        yara_rules, risc_v_flag = get_yara_rule(yara_path, 'func', _length) # rule
        # matching
        _match_res = yara_matching(yara_rules, target) # do matching
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

    #for _addr in sorted(functions.keys()):
    #    print(hex(_addr), ':', functions[_addr])
    #exit(-1)

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
    while True:
        # identifying the function name based on the link order
        id_l_num = 0
        if link_order_flag == True:
            functions, id_l_num = id_func_name_for_linkorder(\
                    functions, target_path, compiler_path, \
                    alias_list, call_map, id_loop_count, exclude_func_list \
                    )
        # identifying the function name based on the dependency
        id_d_num = 0
        if dependency_flag == True:
            functions, id_d_num = id_func_name_for_depend( \
                    functions, call_map, depend_list_path, alias_list \
                    )
        if id_l_num == id_d_num == 0:
            break
        id_loop_count += 1
    else:
        print("cannot access the compiler for the given toolchain : %s" % compiler_path, file=sys.stderr)
    # save checked target dump info
    targets_info = {'name' : target_path, \
            'functions' : functions, \
            'size' : target_size, \
            'base_vaddr' : base_vaddr, \
            }
    match_info = output(targets_info, target_path, 'ida') # output result
    return match_info

def stelftools_create(tc_path, tc_name, arch, tc_compiler_path):
    print('start stelftools : create toolchain items -->')
    start = time.time()
    yara_rule_path = mkrule(tc_path, tc_name)
    depend_list_path, alias_list_path = mkother(tc_path, tc_name)
    #print(yara_rule_path)
    #print(depend_list_path)
    #print(alias_list_path)

    create_toolchain_cfg_file( \
            tc_name, \
            arch, \
            yara_rule_path, \
            tc_compiler_path, \
            alias_list_path, \
            depend_list_path \
            )

    end = time.time()
    print("<-- finish stelftools %.2f seconds" % (end-start))

def stelftools_ident(tc_cfg_path):
    print('start stelftools : function identification -->')
    start = time.time()
    match_info = func_ident(tc_cfg_path)
    overwrite_func_label(match_info)
    end = time.time()
    print("<-- finish stelftools %.2f seconds" % (end-start))

def stelftools_produce(arg=None):
    tc_name = ida_shims.ask_ident("Please input toolchain name", "name")
    tc_compiler_path = ida_shims.ask_file(0, "*", "Please input toolchain compiler path")
    _path = tc_compiler_path.split('/')
    tc_path = "/".join( _path[0:(len(_path)-2)])
    arch = ida_shims.ask_ident("Please input toolchain architecture", "arch")
    #print(tc_name)
    #print(tc_path)
    #print(tc_compiler_path)
    #print(arch)
    if tc_path and tc_name and arch and tc_compiler_path:
        stelftools_create(tc_path, tc_name, arch, tc_compiler_path)

def stelftools_load(arg=None):
    tc_cfg_path = ida_shims.ask_file(0, "*.json", "Load toolchain config file")
    if tc_cfg_path:
        stelftools_ident(tc_cfg_path)

try:
    class ProduceStelftoolsAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)
        def activate(self, ctx):
            stelftools_produce()
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
    class LoadStelftoolsAction(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)
        def activate(self, ctx):
            stelftools_load()
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS
except AttributeError:
    pass

class StelftoolsPlugin(idaapi.plugin_t):
    flags = 0
    comment = "toolchain config file"
    help = ""
    wanted_name = "Stelftools"
    wanted_hotkey = ""
    produce_action_name = 'producestelftools:action'
    load_action_name = 'loadstelftools:action'
    menu_name = "Stelftools toolchain config file..."
    produce_tooltip = "Create stelftools rules, etc."
    load_tooltip = "Load stelftools toolchain config file."
    menu_tab = 'File/'
    menu_context = []

    def init(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            produce_desc = idaapi.action_desc_t(self.produce_action_name,
                                                self.menu_name,
                                                ProduceStelftoolsAction(),
                                                self.wanted_hotkey,
                                                self.produce_tooltip,
                                                150)

            load_desc = idaapi.action_desc_t(self.load_action_name,
                                             self.menu_name,
                                             LoadStelftoolsAction(),
                                             self.wanted_hotkey,
                                             self.load_tooltip,
                                             150)

            idaapi.register_action(produce_desc)
            idaapi.register_action(load_desc)

            idaapi.attach_action_to_menu(
                os.path.join(self.menu_tab, 'Produce file/'),
                self.produce_action_name,
                idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                os.path.join(self.menu_tab, 'Load file/'),
                self.load_action_name,
                idaapi.SETMENU_APP)
        else:
            self.menu_context.append(
                idaapi.add_menu_item(
                    os.path.join(self.menu_tab, 'Produce file/'),
                    "Stelftools toolchain path...", "", 0, stelftools_produce, (None,)))

            self.menu_context.append(
                idaapi.add_menu_item(
                    os.path.join(self.menu_tab, 'Load file/'),
                    "Stelftools toolchain config file...", "", 0, stelftools_load, (None,)))

        return idaapi.PLUGIN_KEEP

    def term(self):
        if idaapi.IDA_SDK_VERSION >= 700:
            idaapi.detach_action_from_menu(
                self.menu_tab, self.produce_action_name)
            idaapi.detach_action_from_menu(
                self.menu_tab, self.load_action_name)
        else:
            if self.menu_context is not None:
                idaapi.del_menu_item(self.menu_context)
        return None

    def run(self, arg):
        return None

    def stelftools_script(self):
        idaapi.IDAPython_ExecScript(self.script, globals())

def PLUGIN_ENTRY():
    return StelftoolsPlugin()
