#!/bin/bash

# ビルドディレクトリが存在する場合は削除
if [ -d build ]; then
    rm -rf build
fi

# ビルドディレクトリを作成
mkdir -p build
cd ./build

# CMakeを実行してMakefileを生成
cmake ..

# ビルドを実行
make

# 実行可能ファイルに実行権限を付与
chmod +x myPcapExecutable

# sudo権限で実行
sudo ./myPcapExecutable