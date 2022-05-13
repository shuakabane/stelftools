# How to Install
stelftools is usable on the command line or as a plugin for IDA Pro or Ghidra.  
### init setup
Install the python3 package used by stelftools and update the paths in scripts.  
```bash
./setup/init.sh
```
## IDA Pro plugin setup
### Install stelftools IDA Plugin
Create a symbolic link to stelftools in the IDA plugin directory.  
```bash
./setup/ida_setup.sh {path to IDA Pro install directory}
```
## Ghidra plugin setup
TBA  

# How to Use
stelftools can be executed in three ways.  
## Command line mode
#### Generate YARA rules and other rules used for matching
```bash
python3 ./libfunc_info_create.py -name {toolchain name} -cp {toolchain compiler path} -arch {toolchain archtecture} 
  or 
python3 ./libfunc_info_create.py -name {toolchain name} -tp {toolchain directory path} -cp {toolchain compiler path} -arch {toolchain archtecture} 
```
- -name: the name of toolchain
- -tp: the path of the toolchain directory (additional)
- -cp: the path of the compiler of a toolchain
- -arch: the architecture of a toolchain
#### Identification of library functions
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

## IDA plugin mode
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

## Ghidra plugin mode  
TBA