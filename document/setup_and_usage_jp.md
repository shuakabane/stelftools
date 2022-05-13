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
TBA

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
#### マッチングに使用するYARAルール等の生成
1. **File** → **Produce file** → **Stelftools toolchain config file...**   
![ida_01.png](images/ida_mk_01.png "01")  
2. ツールチェイン名を入力  
![ida_02.png](images/ida_mk_02.png "02")  
3. ツールチェインのコンパイラを指定  
![ida_03.png](images/ida_mk_03.png "03")  
4. ツールチェインのアーキテクチャを指定  
![ida_04.png](images/ida_mk_04.png "04")  
#### ライブラリ関数の特定  
1. マッチングを行うバイナリをIDA Proで開く  
![ida_01.png](images/usage_ida_01.png "")
2. **File** → **Load file** → **Stelftools toolchain config file...**  
![ida_02.png](images/usage_ida_02.png "")  
![ida_03.png](images/usage_ida_03.png "")  
json形式のツールチェインのコンフィグファイルを指定  
3. マッチング完了  
![ida_04.png](images/usage_ida_04.png "")  
関数名が更新される  

## Ghidra plugin mode
TBA