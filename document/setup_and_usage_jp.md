# How to Install
stelftoolsはコマンドラインやIDA Pro, Ghidraのプラグインとして利用することができます．
### init setup
stelftoolsが使用するpython3 packageのインストール，スクリプト内のパスの更新を行います
```bash
./setup/init.sh
```
## IDA Pro plugin setup
### Install stelftools IDA Plugin  
IDAのプラグインディレクトリにstelftoolsのシンボリックリンクを貼ります  
```bash
./setup/ida_setup.sh {path to IDA Pro install directory}
```
## Ghidra plugin setup  
Ghidraのスクリプトディレクトリにstelftoolsのシンボリックリンクを貼ります  
```bash
./setup/ghidra_setup.sh {path to ghidra install directory}
```

# How to Use  
stelftoolsは3つの実行方法がある
## Command line mode  
#### マッチングに使用するYARAルール等の生成
```bash
python3 ./libfunc_info_create.py -name {toolchain name} -cp {toolchain compiler path} -arch {toolchain archtecture} 
```
- -name: ツールチェインの名称を指定
- -cp: ツールチェインのコンパイラのパスを指定
- -arch: ツールチェインのアーキテクチャを指定
#### ライブラリ関数の特定
```bash
python3 ./func_ident.py -cfg ./toolchain_config/{name of toolchain}.json -target /path/to/target
```
- -cfg: 生成したツールチェインのファイル類が指定されたコンフィグファイルを指定
- -target: マッチングを行うバイナリを指定


## IDA plugin mode
##### Library Function Identification
1. **File** → **Load file** → **Stelftools toolchain config file...**  
2. ツールチェインのコンフィグファイルを選択する  
<img src="images/ida_func_ident.gif" width="90%">  
関数名が更新される  

##### YARA Rules Generation
1. **File** → **Produce file** → **Stelftools toolchain config file...**   
2. ツールチェイン名を入力  
3. ツールチェインのコンパイラを選択  
4. ツールチェインのアーキテクチャを入力  
<img src="images/ida_gen_rule.gif" width="90%">  
ライブラリ関数の特定に使用するYARAルール類が作成される  


## Ghidra plugin mode
##### Library Function Identification
0. **Script Manager** → Scripts/stelftools/python/**ghidra_stelftools.py** → select **func_ident**  
1. ツールチェインのコンフィグファイルを選択する  
<img src="images/ghidra_func_ident.gif" width="90%">  

##### YARA Rules Generation
0. **Script Manager** → Scripts/stelftools/python/**ghidra_stelftools.py** → **make_rules**を選択  
1. ツールチェイン名を入力  
2. ツールチェインのディレクトリを選択  
3. ツールチェインのコンパイラを選択  
4. ツールチェインのアーキテクチャを入力  
<img src="images/ghidra_makes.gif" width="90%">
