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
#### Generate YARA rules, etc. to be used for matching
1. **File** → **Produce file** → **Stelftools toolchain config file...**   
![ida_01.png](images/ida_mk_01.png "01")  
2. Input toolchain name  
![ida_02.png](images/ida_mk_02.png "02")  
3. Specifying the compiler of the toolchain  
![ida_03.png](images/ida_mk_03.png "03")  
4. Identification of library functions  
![ida_04.png](images/ida_mk_04.png "04")  
#### Identification of library functions  
1. Open the binary for identification of library functions in IDA Pro    
![ida_01.png](images/usage_ida_01.png "")  
2. **File** → **Load file** → **Stelftools toolchain config file...**  
![ida_02.png](images/usage_ida_02.png "")  
![ida_03.png](images/usage_ida_03.png "")  
Select toolchain config file in json format  
3. completed  
![ida_04.png](images/usage_ida_04.png "")  
update function name  

## Ghidra plugin mode  
TBA