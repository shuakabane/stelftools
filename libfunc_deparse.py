#!/usr/bin/python3
import re
import os
import sys
import arpy
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
import magic
import argparse

def debugprint_list(s_list):
    print('dbg print --->')
    for s in s_list:
        print(s)
    print('<--- dbg print')

def del_alias_funcname(funcname):
    alias_list = ['__GI_', '__libc_']
    for _alias in alias_list:
        funcname  = re.sub(_alias, '', funcname)
    return funcname

def check_reltab(e):
    availability_of_rel = False # avaliability of relocation table
    for section in e.iter_sections():
        if isinstance(section, RelocationSection):
            availability_of_rel = True
    return availability_of_rel

def get_symtab(e):
    symtab_list = []
    section = e.get_section_by_name('.symtab')
    if isinstance(section, SymbolTableSection):
        symbols = e.get_section(section.header.sh_link)
        for st_index, sym in enumerate(section.iter_symbols()):
            st_value = sym['st_value'] # offset
            st_size  = sym['st_size']
            st_type  = sym['st_info']['type']
            st_bind  = sym['st_info']['bind']
            st_vis   =  sym['st_other']['visibility']
            st_ndx   =  sym['st_shndx']
            st_name  = sym.name
            #print(st_index, st_value, st_size, st_type, st_bind, st_vis, st_ndx, st_name)
            symtab_list.append([ \
                    st_index, st_value, st_size, st_type, st_bind, st_vis, st_ndx, st_name \
                    ])
    #debugprint_list(symtab_list)
    return symtab_list

def get_reltab(e):
    reltab_dict = {} # save relocation table section num and function name
    # get only relocation table
    for i, section in enumerate(e.iter_sections()):
        if not isinstance(section, RelocationSection): # skip the not relocation table
            continue
        #print(i-1, section.name) # dbg
        reltab_dict[i-1] = section.name # i-1 == real section number
    return reltab_dict

def uniq_symtab_list(symtab_list):
    uniq_list = []
    uniq_key_list = []
    for st_ndx, _, st_value, st_size in symtab_list:
        uniq_key_list.append([st_ndx, st_value, st_size])
    uniq_key_list = sorted(list(map(list, set(map(tuple, uniq_key_list)))))
    for ndx, value, size in uniq_key_list:
        st_list = []
        for st_ndx, st_name, st_value, st_size in symtab_list:
            if ndx == st_ndx and value == st_value and size == st_size:
                st_list.append([st_ndx, st_name, st_value, st_size])
        if len(st_list) == 1: # add only uniq section num
            uniq_list.append([ndx, st_list[0][1], value, size])
        elif len(st_list) > 1: # add only the shortest function per section num
            name_list = sorted([x[1] for x in st_list])
            name = ','.join(name_list)
            uniq_list.append([ndx, name, value, size])
        else: # irregular
            print('unknown case : [func] uniq_symtab_list', file=sys.stderr)
            exit(1)
    return uniq_list

def analy_symtab(e, fname, symtab_list, reltab_dict):
    object_rel_info_dict= {}
    symtab_func_section_info = []
    for st_index, st_value, st_size, st_type, st_bind, st_vis, st_ndx, st_name in symtab_list:
        if st_type == 'STT_FUNC' and type(st_ndx) == int:
            #print(st_index, st_value, st_size, st_type, st_bind, st_vis, st_ndx, st_name) # dbg
            symtab_func_section_info.append([st_ndx, st_name, st_value, st_size])
    symtab_list = uniq_symtab_list(symtab_func_section_info)
    #debugprint_list(symtab_list) # dbg
    for st_ndx, st_name, st_value, st_size in symtab_list:
        _object_rel_info_list = []
        caller = st_name
        #print(caller)
        start = st_value
        end = st_value+st_size-1
        try :
            section = e.get_section_by_name(reltab_dict[st_ndx])
        except KeyError: # case with no corresponding section
            #print(fname)
            #print("not find the section to the section number in the object file : %s" % (fname), file=sys.stderr)
            continue
        symbols = e.get_section(section.header.sh_link)
        #print("%s : 0x%x ~ 0x%x" % (caller, start, end))
        for rel in section.iter_relocations():
            if rel['r_info_type'] == 16: # R_386_TLS_GOTIE
                continue
            #callee = del_alias_funcname(symbols.get_symbol(rel.entry['r_info_sym']).name)
            callee = symbols.get_symbol(rel.entry['r_info_sym']).name
            if start <= rel['r_offset'] <= end and len(callee):
                r_offset = rel['r_offset'] - start
                _object_rel_info_list.append([callee, r_offset])

        object_rel_info_dict[caller] = _object_rel_info_list
    #print(object_rel_info_dict)
    return object_rel_info_dict

def func_depend_analy(f, fname):
    e = ELFFile(f)
    #print(fname) # dbg
    depend_func_list = {}
    symtab_list = get_symtab(e)
    if not check_reltab(e): # if the relocation table dose not exist
        return depend_func_list
    reltab_dict = get_reltab(e)
    object_rel_info_dict = analy_symtab(e, fname, symtab_list, reltab_dict)
    return object_rel_info_dict

def fetch_object_arfile(arfile): # for archive file
    rel_arfile = arfile.split('/')[-1]
    arfile = os.path.abspath(arfile)
    objfiles = arpy.Archive(arfile)
    return objfiles

def output_dlist(depend_list, depend_list_output_path):
    with open(depend_list_output_path, 'wt') as f:
        for i in range(len(depend_list)):
            f.write(' '.join([str(j) for j in depend_list[i]]) + "\n")

def output_alist(depend_list, alias_list_output_path):
    alias_list = []
    for depend in depend_list:
        if ',' in depend[0] and depend[0] not in alias_list:
            alias_list.append(depend[0])
    with open(alias_list_output_path, 'wt') as f:
        for alias in sorted(alias_list):
            #print(alias)
            if ',' in alias:
                #print(alias[0])
                f.write(alias + "\n")

def output_depend(depend_list):
    for i in range(len(depend_list)):
        #print(depend_list[i])
        print(' '.join([str(j) for j in depend_list[i]]))

def check_not_func_list(callee_funcname):
    no_func_list = ['_gp_disp', '_GLOBAL_OFFSET_TABLE_']
    # print(callee_funcname) # dbg
    if callee_funcname in no_func_list: # if the callee function name is not function
        return False
    return True

def check_mips64_self_calling(callers, callee):
    if callee in callers.split(','):
        #print(callers, callee)
        return False
    return True

def fmt_depend_data(depend_list):
    formatted_depend_data = []
    for caller, callee_list in depend_list.items():
        for callee, offset in callee_list:
            if check_not_func_list(callee) \
                    and check_mips64_self_calling(caller, callee):
                formatted_depend_data.append([caller, callee, offset]) # int
                # formatted_depend_data.append([caller, callee, hex(offset)]) # hex
    return formatted_depend_data

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('[WORNING] : Please input the path to the static library')
        exit(1)
    # format arg
    parser = argparse.ArgumentParser(prog = sys.argv[0])
    parser.add_argument('files', nargs = '+', help = 'File name of archive, object, executable file')
    parser.add_argument('--output', '-o', choices = ['stdout', 'dot', 'graph', 'no'], default = 'no', help = 'output function dependency')
    args = parser.parse_args()
    # make depend_list
    depend_list = {}
    for filename in args.files:
        #print(filename) # debug
        ftype = magic.from_file(filename, mime = True)
        if ftype == 'application/x-object': # .o file
            with open(filename, 'rb') as f:
                fname =  filename.split('/')[-1]
                depend_list.update(func_depend_analy(f, fname))
        elif ftype == 'application/x-archive': # .a file
            objfiles = fetch_object_arfile(filename)
            for f in objfiles:
                fname = f.header.name.decode('utf-8')
                depend_list.update(func_depend_analy(f, fname))
    formatted_depend_data = fmt_depend_data(depend_list)
    # choice output format
    if args.output == 'stdout':
        output_depend(formatted_depend_data)
    elif args.output == 'dot':
        output_dot_depend(formatted_depend_data)
    elif args.output == 'graph':
        gen_depend_graph(formatted_depend_data)
    elif args.output == 'no':
        None
