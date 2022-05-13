#! /usr/bin/env python3
# usage: DubMaker.py [-h] --funclist_path FUNCLIST_PATH --toolchain_path TOOLCHAIN_PATH

import os
import re
import sys
import subprocess
import argparse

STELFTOOLS_PATH="/path/to/stelftools/"

def get_funclist(funclist_path):
    with open(funclist_path, 'r') as f:
        funclist = [s.strip() for s in f.readlines()]
    f.close()
    # print(funclist) # dbg
    return funclist

#import time
def get_func_include_and_macro(funclist):
    #s_time = time.time() # dbg
    func_man_res_dict = {}
    include_list = []
    macro_list = [] 
    no_man_func_list = []
    exclude_error_func_list = []
    for func in funclist: # get function man list
        func_man_path = STELFTOOLS_PATH + '/_tmpdir/man_datasets/' + func + '.man'
        if os.path.exists(func_man_path): # road link func man
            # load man result
            with open(func_man_path, 'r') as man_f:
                man_res_list = [s.strip() for s in man_f.readlines()]
                if len(man_res_list) == 0:
                    no_man_func_list.append(func)
                    #print('delete 3 :', func)
                    exclude_error_func_list.append(func)
                    continue
                func_man_res_dict[func] = man_res_list
        else:
            man_res = subprocess.Popen(['man', '3', func], shell=False, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            man_stdout, man_stderr = man_res.communicate()
            if len(man_stdout) == 0 and len(man_stderr) > 0:
                man_res = subprocess.Popen(['man', '2', func], shell=False, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                man_stdout, man_stderr = man_res.communicate()
                if len(man_stdout) == 0 and len(man_stderr) > 0: # man not found function list
                    no_man_func_list.append(func)
                    #print('delete 4 :', func)
                    exclude_error_func_list.append(func)
                    continue
            man_res_list = man_stdout.splitlines()
            func_man_res_dict[func] = man_res_list
            # save man result
            with open(func_man_path, 'w') as man_f:
                for man_res in man_res_list:
                    man_f.write("%s\n" % man_res)

        #print('%s : %s' % (func, len(man_res_list)))
    #for k, v in func_man_res_dict.items():
    #    print(k, len(v))

    for funcname, man_list in func_man_res_dict.items(): # search include and macro
        for man_line in man_list:
            if '#include' in man_line:
                #print(funcname, " ".join(man_line.split())) # dbg
                include_list.append(" ".join(man_line.split()).split('/*')[0].rstrip())
            if '#define' in man_line and not '\\' in man_line and not re.search(r'\|', man_line): #not '|' in man_list:
                #print(funcname, " ".join(man_line.split())) # dbg
                macro_list.append((" ".join(man_line.split()).split('/*')[0]).rstrip())
    include_list = sorted(set(include_list))
    macro_list = sorted(set(macro_list))
    #print('man time : %f' % (time.time() - s_time), file=sys.stderr) # dbg
    return include_list, macro_list, no_man_func_list, exclude_error_func_list

def make_source_list(include_list, macro_list, func_list, no_man_func_list):
    macro_list = ['#define _LARGEFILE64_SOURCE', '#define _GNU_SOURCE'] # dbg
    # check added header
    xdr_func = [func for func in func_list if func.startswith('xdr')]
    authnone_func = [func for func in func_list if func.startswith('authnone')]
    #pthread_func = [func for func in func_list if func.startswith('pthread')]
    if len(xdr_func) > 0:
        macro_list.append('#include <rpc/xdr.h>') # dbg
    if len(authnone_func) > 0:
        macro_list.append('#include <rpc/rpc.h>') # dbg
    #if len(pthread_func) > 0:
    #    macro_list.append('#include <pthread>') # dbg
    # check thread option
    #compile_option = []
    #pthread_func = [func for func in func_list if func.startswith('pthread')]
    #if len(pthread_func) > 0:
    #    compile_option.append('-lpthread')

    main_header = ['int main () {', '\tvoid* p;']
    main_footer = ['}']
    real_func_list = list(set(func_list) - set(no_man_func_list))
    main_inner = ['\tp = ' + s + ';' for s in real_func_list]
    c_source_list = macro_list + include_list + main_header + main_inner + main_footer
    #make_c_source(c_source_list)
    return c_source_list
    #return c_source_list, compile_option

def make_c_source(c_source_list, dummy_bin_name):
    dummy_binary_path = STELFTOOLS_PATH + '/_tmpdir/dummy_bin/' + dummy_bin_name + '.c'
    if os.path.exists(dummy_binary_path):
        os.remove(dummy_binary_path) # remove if it already exists.
    with open(dummy_binary_path, 'w') as source_f:
        for c_source in c_source_list:
            source_f.write("%s\n" % c_source)
    return True

#def build_source(toolchain_path, c_source_list, dummy_bin_name, compile_option, exclude_error_func_list):
def build_source(toolchain_path, c_source_list, dummy_bin_name, exclude_error_func_list):
    compile_option = ['-lpthread']
    LIMIT_LOOP = 10000
    loop_count = 0
    while True:
        make_c_source(c_source_list, dummy_bin_name)
        error_func_list = []
        dummy_bin_path = STELFTOOLS_PATH + '/_tmpdir/dummy_bin/' + dummy_bin_name
        dummy_source_path = STELFTOOLS_PATH + '/_tmpdir/dummy_bin/' + dummy_bin_name + '.c'
        if len(compile_option) != 0:
            compile_stdout, compile_stderr = subprocess.Popen( \
                    [toolchain_path, '-o', dummy_bin_path, '-static', ''.join(compile_option), dummy_source_path], \
                    shell=False, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        else:
            compile_stdout, compile_stderr = subprocess.Popen( \
                    [toolchain_path, '-o', dummy_bin_path, '-static', dummy_source_path], \
                    shell=False, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


        if not bool(len(compile_stderr)):
            break
        c_stderr_list = compile_stderr.splitlines()

        #print('---')
        #for c_stderr in c_stderr_list:
        #    print(c_stderr)
        #print('---')

        if 'Value too large for defined data type' in c_stderr_list[0]:
            print('[DubMaker] error : Value too large for defined data type : %s' % toolchain_path , file=sys.stderr)
            exit(-1)

        # warning only check
        if 'main' in c_stderr_list[0]:
            #print(c_stderr_list)
            all_err_num = len((c_stderr_list)) - 1
            warn_num = 0
            for i in range(all_err_num):
                #print(i, c_stderr_list[i+1])
                if 'warning' in c_stderr_list[i+1]:
                    warn_num += 1
            #print(all_err_num, warn_num)
            if all_err_num == warn_num:
                break
        # get error function
        for c_stderr in c_stderr_list:
            if 'relocation truncated to fit: R_SPARC_13 against symbol' in c_stderr:
                try:
                    compile_option.remove('-lpthread')
                except ValueError:
                    pass
                #print(c_stderr)
            if '-lpthread' in c_stderr:
                #print('e', c_stderr)
                try:
                    compile_option.remove('-lpthread')
                except ValueError:
                    pass
            if 'undeclared (first use in this function)' in c_stderr:
                error_func_list.append(re.sub('\'|‘|’', '', c_stderr.split(' ')[2]))
                #print('delete a :', re.sub('\'|‘|’', '', c_stderr.split(' ')[2]))
            elif 'undefined reference to ' in c_stderr:
                error_func_list.append(re.sub('\'|‘|’|`|', '', c_stderr.split(' ')[4]))
                #print('delete b :', re.sub('\'|‘|’', '', c_stderr.split(' ')[2]))
            elif '#include' in c_stderr:
                #print(c_stderr)
                #print(re.sub('^ ', '', c_stderr))
                err_header = re.sub('^ ', '', c_stderr)
                #print('delete c :', re.sub('\'|‘|’', '', c_stderr.split(' ')[2]))
                error_func_list.append(err_header)
            elif 'h: No such file or directory' in c_stderr:
                #print('-')
                err_header_square = '#include <' + c_stderr.split(':')[4].split(' ')[1] + '>'
                err_header_dquote = '#include "' + c_stderr.split(':')[4].split(' ')[1] + '"'
                #print(err_header)
                error_func_list.append(err_header_square)
                error_func_list.append(err_header_dquote)
                #print('delete d :', re.sub('\'|‘|’', '', c_stderr.split(' ')[2]))

        for error_func in error_func_list:
            #exclude_error_func_list.append(error_func)
            for undec_index, c_source in enumerate(c_source_list):
                if error_func+';' in c_source and not error_func == 'void* p':
                    #print('delete 1 :', error_func, c_source)
                    del c_source_list[undec_index]
                    exclude_error_func_list.append(error_func)
                elif error_func.startswith('#include') and error_func in c_source:
                    #print('delete 2 :', error_func, c_source)
                    del c_source_list[undec_index]
                    #print(error_func, undec_index)
                    exclude_error_func_list.append(error_func)
        loop_count += 1
        #print(loop_count)
        #print(os.path.exists(dummy_bin_path))
        if loop_count > LIMIT_LOOP or os.path.exists(dummy_bin_path):
            if os.path.exists(dummy_bin_path):
                return True, exclude_error_func_list
            else:
                print('[DubMaker] error : build source loop limit (%s)' % dummy_bin_name, file=sys.stderr)
                exit(-1)
    if os.path.exists(dummy_bin_path):
        return True, exclude_error_func_list
    else:
        return False, exclude_error_func_list

def get_func_order_list(dummy_bin_name):
    nm_dict = {}
    nm_list = []
    nm_addr_list = []
    func_order_list = []
    dummy_bin_path = STELFTOOLS_PATH + '/_tmpdir/dummy_bin/' + dummy_bin_name
    nm_stdout, nm_stderr = subprocess.Popen( \
            'nm ' + dummy_bin_path + ' | grep -v "^ " | grep -v "\$[a-z]$" ', \
            shell=True, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    for s in nm_stdout.splitlines():
        s_list = s.split(' ')
        nm_list.append([int(s_list[0], 16), s_list[2]])
        #print(int(s_list[0], 16), s_list[1], s_list[2]) # dbg
        nm_addr_list.append(int(s_list[0], 16))
    nm_addr_list = sorted(set(nm_addr_list))
    for nm_addr in nm_addr_list:
        tmp_nm_list = []
        for nm_l in nm_list:
            if nm_addr == nm_l[0]:
                tmp_nm_list.append(nm_l[1])
        nm_dict[nm_addr] = tmp_nm_list
    for addr, func_list in nm_dict.items():
        func_order_list.append(min(func_list, key=len))
    return func_order_list

#tmp
def get_only_global_sym_func_order_list(dummy_bin_name):
    nm_dict = {}
    nm_list = []
    nm_addr_list = []
    global_sym_func_order_list = []
    dummy_bin_path = STELFTOOLS_PATH + '/_tmpdir/dummy_bin/' + dummy_bin_name
    nm_stdout, nm_stderr = subprocess.Popen( \
            'nm ' + dummy_bin_path + ' | grep -v "^ " | grep -v "\$[a-z]$" | grep " T " ', \
            shell=True, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    for s in nm_stdout.splitlines():
        s_list = s.split(' ')
        nm_list.append([int(s_list[0], 16), s_list[2]])
        #print(int(s_list[0], 16), s_list[1], s_list[2]) # dbg
        nm_addr_list.append(int(s_list[0], 16))
    nm_addr_list = sorted(set(nm_addr_list))
    for nm_addr in nm_addr_list:
        tmp_nm_list = []
        for nm_l in nm_list:
            if nm_addr == nm_l[0]:
                tmp_nm_list.append(nm_l[1])
        nm_dict[nm_addr] = tmp_nm_list
    for addr, func_list in nm_dict.items():
        global_sym_func_order_list.append(min(func_list, key=len))
    return global_sym_func_order_list

def output_func_order_list(func_order_list):
    order_list_path = './dummy_binary_order.txt'
    if os.path.exists(order_list_path):
        os.remove(order_list_path) # remove if it already exists.
    with open(order_list_path, 'w') as func_list_f:
        for func_order in func_order_list:
            func_list_f.write("%s\n" % func_order)
    return True

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--funclist_path', '-fl', help = 'Path to link function list', required=True)
    parser.add_argument('--toolchain_path', '-tp', help = 'Path to use toolchain', required=True)
    parser.add_argument('--debug', '-d', action = 'store_true', help = 'Not delete output file')
    args = parser.parse_args()
    return args

# module call func
def get_order_list(func_list, toolchain_path, dummy_bin_name):
    func_order_list = []
    global_sym_func_order_list = []
    include_list, macro_list, no_man_func_list, exclude_error_func_list = get_func_include_and_macro(func_list)
    #c_source_list, compile_option = make_source_list(include_list, macro_list, func_list, no_man_func_list)
    c_source_list = make_source_list(include_list, macro_list, func_list, no_man_func_list)
    b_flag, exclude_error_func_list = build_source(toolchain_path, c_source_list, dummy_bin_name, exclude_error_func_list)
    if b_flag == True:
        func_order_list = get_func_order_list(dummy_bin_name)
        global_sym_func_order_list = get_only_global_sym_func_order_list(dummy_bin_name)
        #output_file_list = ['./dummy_binary', './dummy_binary.c'] # del use file list
        #for output_file in output_file_list:
        #    os.remove(output_file) # del file
        # output_func_order_list(func_order_list) # dbg
    return func_order_list, global_sym_func_order_list, exclude_error_func_list

if __name__ == '__main__':
    args = arg_parser()
    func_list = get_funclist(args.funclist_path)
    include_list, macro_list, no_man_func_list, exclude_error_func_list = get_func_include_and_macro(func_list)
    c_source_list = make_source_list(include_list, macro_list, func_list, no_man_func_list)
    if build_source(args.toolchain_path, c_source_list, 'debug-test', exclude_error_func_list) == True:
        func_order_list = get_func_order_list('debug-test')
    if not args.debug:
        for func_order in func_order_list:
            print(func_order)
        output_file_list = ['./dummy_binary', './dummy_binary.c', 'dummy_binary_order.txt']
        for output_file in output_file_list:
            os.remove(output_file)
    else:
        output_func_order_list(func_order_list)

