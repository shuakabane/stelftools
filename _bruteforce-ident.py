#!/usr/bin/env python3
import os
import sys
import glob
import json
import argparse
import subprocess

def set_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-arch', help = 'input the architecture of the toolchain to brute force')
    parser.add_argument('-target', help = 'target path')
    parser.add_argument('-verbose', '-v', action='store_true')
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    TOOLCHAIN_CONFIG_DIR_PATH = "./toolchain_config/"
    args = set_args()
    target_arch = ''
 
    if args.arch == False:
        print("error: please choice architecture")
        exit(-1)

    match_num_list = []
    for tc_cfg_path in sorted(glob.glob(TOOLCHAIN_CONFIG_DIR_PATH + "*.json")):
        with open(tc_cfg_path) as tc_cfg_fp:
            cfg_info = json.load(tc_cfg_fp)
        target_arch = cfg_info['arch']
        if target_arch == args.arch:
            cmd = ["python3", "func_ident.py", "-cfg", tc_cfg_path, "-target", args.target]
            cmd_log = subprocess.run(cmd,stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            if len(cmd_log.stderr.decode("utf8")) != 0:
                #print(cmd_log.stderr.decode("utf8"))
                continue
            log_list = []
            for _log_line  in cmd_log.stdout.decode("utf8").split('\n'):
                log_list.append( (" ").join(_log_line.split(' ')[1:]) )
            match_num_list.append([tc_cfg_path, len(set(log_list))])

    _, best_match_num = sorted(match_num_list, reverse=True, key=lambda x: x[1])[0]

    print("Number of most matched functions: %d" % best_match_num)
    print("Candidates for toolchain ->")
    for tc_cfg_path, match_num in sorted(match_num_list, reverse=True, key=lambda x: x[1]):
        if match_num == best_match_num or args.verbose == True:
            print(tc_cfg_path, match_num)
