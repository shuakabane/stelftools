stelftools
====
パターンマッチングによって静的結合されたライブラリ関数を特定するために必要なツールやルール
stelftools is a set of tools and rules needed to identify statically linked library functions by pattern matching.

## File Description
* ghidra_export_funclist :
ライブラリ関数の特定結果をghidraで読み込める形式にエクスポートしたもの
* yara-patterns :
ライブラリ関数の特定に必要なルール<br>
`./yara-patterns/short`短い関数のルールを含む<br>
`./yara-patterns/short`短い関数のルールを含まない
* sample_toolchain :
検体名と検体のビルドに使用されたツールチェイン名のリスト

## Paper
[Identification of library functions statically linked to Linux malware without symbols](https://www.sciencedirect.com/science/article/pii/S1877050920319487) (2020)
<br>
[シンボル情報が消去されたIoTマルウェアに静的結合されたライブラリ関数の特定](http://id.nii.ac.jp/1001/00208402/) (2020)
