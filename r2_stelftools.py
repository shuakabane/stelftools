import r2pipe, sys, subprocess, os
from termcolor import colored
from pyfzf.pyfzf import FzfPrompt

STELFTOOLS_PATH="/home/lilium/src/github.com/n01e0/stelftools/"
STELFTOOLS_TOOLCHAIN_PATH = STELFTOOLS_PATH + 'toolchain_config/'

def createR2Pipe():
    try:
        pipe = r2pipe.open()
        pipe.cmd('a')
        return pipe
    except:
        print(f'Unexpected error: {sys.exc_info()[0]}')
        return None

pipe = createR2Pipe()

if pipe is None:
    print(colored("only callable inside a r2-instance!", "red", attrs=["bold"]))
    exit(0)

fzf = FzfPrompt()

known_toolchain_list = [x.name for x in os.scandir(STELFTOOLS_TOOLCHAIN_PATH)]

arch = str(pipe.cmdj('ij')['bin']['arch'])
target = str(pipe.cmdj('ij')['core']['file'])

print('which toolchain?')
toolchain = fzf.prompt(known_toolchain_list)[0]
print(f'{toolchain} selected!')

if toolchain not in known_toolchain_list and toolchain + '.json' not in known_toolchain_list:
    print(colored("toolchain not found", "red"))
    print('toolchain json path?')
    toolchain = input('> ')
else:
    toolchain = str(STELFTOOLS_TOOLCHAIN_PATH + toolchain)

run_cmd = [ \
            'python3', str(STELFTOOLS_PATH + 'func_ident.py'), \
            '-cfg', toolchain, \
            '-target', f'./{target}', \
            '-o', 'ghidra']

cmd_res = subprocess.check_output(run_cmd).split(b'\n')
res_list = [x.decode('utf-8') for x in cmd_res if x != b'']

for res in res_list:
    addr = res.split(':')[0]
    funcname = res.split(':')[1]
    print(f'{addr}:{funcname}')
    pipe.cmd(f'afn {funcname} @{addr}') 
