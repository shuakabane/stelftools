# stelftools: cross-architecture static library detector for IoT malware

## Description

`stelftools` is a signature matching tool for identifying statically-linked library functions for IoT malware. Detecting library functions in IoT malware is essential because most IoT malware is likely to contain a certain amount of code of library functions, which we do not need to read for analysis. `stelftools` reduces the effort of analysts to read such a part of code by correctly identifying and annotating them with their symbol name. 
The figure below shows that `stelftools`(IDA plugin mode) recognizes many functions and turns their names, which are started with "sub_", into their symbol name, highlighted by green. 

<div align="center">
<img src="images/func_ident_result.png" width="80%" title="Identification of functions by stelftools for IDA Plugin">
</div>

`stelftools` comprises a matching tool and a set of Yara signatures supporting the following 17 architectures and 637 toolchains. We can cover almost all types of toolchains we can see in current IoT malware with these signatures. Specifically, we could identify the all toolchain of 3,991 IoT malware that we had collected using our IoT honeypots. Additionally, we provide a tool for generating a Yara signature from a given toolchain just in the case when malware is built with a toolchain that is not covered by these signatures. 

- Supported Architecture
  - ARC
  - ARM / AArch64
  - MIPS / MIPSEL / MIPS64 / MIPS64EL
  - Motorola 68000
  - PowerPC / PowerPC64
  - RISC-V 32 / RISC-V 64
  - SuperH
  - SPARC / SPARC64
  - Intel 80386 / x86_64

Moreover, we developed several heuristics based on our observation of compiler and linker behaviors into `stelftools` to reduce false detection. We then achieved the highest detection accuracy, i.e., 99.8%, compared to publicly available tools for statically-linked library function detection, such as IDA FLIRT [1], BinDiff [2], or rizzo [3].

We can use `stelftools` as a command-line tool or a plugin for a reverse engineering tool of IDA and Ghidra. We believe it would be a best friend for practitioners to keep close with and use in their daily IoT malware analysis.

## Features
`stelftools` is composed of the following three parts: pattern matcher, Yara signatures, and generator. 

- Pattern Match (`func_ident.py`, `ida_stelftools.py`, `ghidra_stelftools.py`)
  - It receives an ELF binary as an input, and then it outputs a list of detected functions' address and name. 
  - It has several heuristics to recude false detection. 
    - Exclude detection on the basis of short rules
    - Exclude detection occured ouside of user-defined areas.
    - Prioritize based on library function dependencies and link order. 
  - You can also invoke this script from a reverse engineering tools, such as IDA or Ghidra, as well as using as a command-line tool. 

- Yara Signatures (`yara-patterns`)
  - We generated 637 Yara signatures for 17 architectures and 637 toolchains in advanced and published them in the `stelftools` repository. 
  - We can cover almost all toolchain used in current IoT malware dataset with these signatures. 

- Pattern Generation (`libfunc_info_create.py`)
  - It receives a toolchain path as an input, i.e., a path to a directory containing .a and .o files (static library files), and then it outpus Yara rules for detecting the library functions of the static library files. 
  - It generates a set of flexible rules supporting relocation, optimization and linker relaxation to achieve a high detection accuracy. 


## Comparison with other function identification tools

We have compared `stelftools` with other tools for statically-linked library function detection, IDA FLIRT [1], BinDiff [2], and rizzo [3], using the dataset composed of `150` malware samples. 
The below table shows the result of the comparision. As you can see, `stelftools` achieves the highest detection accuracy indicating that it correctly detected 98% of the statically-linked functions used in the dataset, while the others did around a `92.27%` accuracy.

| `stelftools` | IDA FLIRT | BinDiff | rizzo  |
| ------------ | ----------| --------| -------|
| 92.27%       | 86.59%    | 72.80%  | 80.35% |

## Requirement
### python3 package
|  Package    | Version |
|:------------|:--------|
| [arpy](https://pypi.org/project/arpy/)                 | 2.2.0  |
| [yara-python](https://pypi.org/project/yara-python/)   | 4.2.0  |
| [capstone](https://pypi.org/project/capstone/)         | 4.0.2  |
| [pyelftools](https://pypi.org/project/pyelftools/)     | 0.28   |
| [python-magic](https://pypi.org/project/python-magic/) | 0.4.25 |
| [cxxfilt](https://pypi.org/project/cxxfilt/)           | 0.3.0  |

## Usage 
### How to Install

#### init setup

To install necessary python3 packages and configure the paths used in tools.  

```bash
./setup/init.sh
```

#### IDA Pro plugin setup (Needed when you use in IDA plugin mode)

To make a symblic link in the IDA's plugin directory to stelftools.

```bash
./setup/ida_setup.sh {path to IDA Pro install directory}
```

### How to Use

#### Command line mode  

##### Library Function Identification

```bash
python3 ./func_ident.py -cfg ./toolchain_config/{name of toolchain}.json -target /path/to/target
```
- -cfg: the config file for a toolchain 
  - *Recommendation*
    - When you do not know which toolchain you should specify for your analysis, we recommend to try to specify the toolchain in the following order because our previous study [4] shows the trend of toolchain used in IoT malware.  
      - firmware linux 0.9.6, i.e. `fl-0.9.6_{arch}`
      - firmware linux, i.e. `fl-{0.9.7 ~ 0.9.11}_{arch}`
      - aboriginal linux, i.e., `al-{1.0.0 ~ 1.4.5}_{arch}`
      - bootlin, i.e., `bootlin_{arch}--{libc}--{version}`
      - other
- -target: the binary path to be analyzed

Example
```bash
$ python3 ./func_ident.py -cfg ./toolchain_config/ucli-pub-0.9.30.1_i586.json -target ./sample/main.i586
0x8048094 : crt tp : _fini, _init 15
0x80480b0 : crt tp : __get_pc_thunk_bx 4
0x80480c0 : crt tp : __do_global_dtors_aux 161
0x8048164 : crt tp : _start 34
0x80481b8 : lib tp : puts 124
0x8048234 : lib tp : _stdio_init 97
0x8048295 : lib tp : __stdio_init_mutex 23
0x80482ac : lib tp : _stdio_term 136
0x8048334 : lib tp : __stdio_wcommit 43
0x8048360 : lib tp : putc_unlocked 197
0x8048428 : lib tp : fputs_unlocked 51
0x804845c : lib tp : fwrite_unlocked 116
0x80484d0 : lib tp : memcpy 39
0x80484f8 : lib tp : strlen 19
0x804850c : lib tp : isatty 29
0x804852c : lib tp : tcgetattr 112
0x804859c : lib tp : __uClibc_fini 63
0x80485db : lib tp : __pthread_return_0 3
0x80485de : lib tp : __pthread_return_void 1
0x80485df : lib tp : __check_one_fd 52
0x8048613 : lib tp : __uClibc_init 64
0x8048653 : lib tp : __uClibc_main 441
0x804880c : lib tp : open 75
0x8048857 : lib tp : creat 25
0x8048870 : lib tp : getuid 38
0x8048898 : lib tp : fcntl 87
0x80488f0 : lib tp : ioctl 63
0x8048930 : lib tp : fcntl64 63
0x8048970 : lib tp : getegid 38
0x8048998 : lib tp : geteuid 38
0x80489c0 : lib tp : getgid 38
0x80489e8 : lib tp : __errno_location 6
0x80489f0 : lib tp : __stdio_WRITE 126
0x8048a70 : lib tp : __stdio_fwrite 240
0x8048b60 : lib tp : __stdio_trans2w_o 158
0x8048c00 : lib tp : memchr 35
0x8048c24 : lib tp : memset 21
0x8048c3c : lib tp : memrchr 176
0x8048cec : lib tp : mempcpy 33
0x8048d10 : lib tp : abort 273
0x8048e24 : lib tp : exit 103
0x8048e8c : lib tp : _dl_aux_init 18
0x8048eaf : lib tp : sigaction 217
0x8048f88 : lib tp : __syscall_rt_sigaction 59
0x8048fc4 : lib tp : write 54
0x8048ffc : lib tp : sigprocmask 85
0x8049054 : lib tp : _exit 40
0x804907c : lib tp : fseek 27
0x8049098 : lib tp : fseeko64 227
0x804917c : lib tp : __stdio_adjust_position 168
0x8049224 : lib tp : __stdio_seek 51
0x8049258 : lib tp : raise 24
0x8049270 : lib tp : __sigismember 36
0x8049294 : lib tp : __sigaddset 32
0x80492b4 : lib tp : __sigdelset 32
0x80492d4 : lib tp : getpid 38
0x80492fc : lib tp : kill 50
0x8049330 : lib tp : lseek64 95
0x8049390 : crt tp : __do_global_ctors_aux 38
0x80493b8 : crt tp : _fini, _init 15
```

##### YARA Rules Generation

First of all, you have to prepare a compiled toolchain and then run the following commands. 

```bash
python3 ./libfunc_info_create.py -name {toolchain name} -cp {toolchain compiler path} -arch {toolchain archtecture} 
```
- -name: the name of toolchain
- -cp: the path of the compiler of a toolchain
- -arch: the architecture of a toolchain

#### IDA plugin mode  

##### Library Function Identification
1. **File** → **Load file** → **Stelftools toolchain config file...**  
2. open toolchain config file 
<img src="images/ida_func_ident.gif" width="90%">

##### YARA Rules Generation
1. **File** → **Produce file** → **Stelftools toolchain config file...**   
2. input toolchain name    
3. choose toolchain compiler path  
4. input toolchain architecture  
<img src="images/ida_gen_rule.gif" width="90%">


#### Ghidra plugin mode  
See the following link. https://github.com/shuakabane/stelftools

## License 
MIT License

## References
- [1] IDA https://hex-rays.com/products/ida/tech/flirt/ 
- [2] BinDiff https://www.zynamics.com/bindiff.html 
- [3] rizzo https://github.com/tacnetsol/ida 
- [4] "Identification of toolchains used to build IoT malware with statically linked libraries" https://doi.org/10.1016/j.procs.2021.09.291 
