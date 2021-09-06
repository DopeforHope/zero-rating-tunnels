#!/bin/bash

apt-get update
apt-get upgrade -y
apt-get install -y python3-pip git

# installing teletun + requirements
pip3 install python-pytun
pip3 install git+https://github.com/DopeforHope/python-telegram.git


# install newest libtd
apt-get install -y make git zlib1g-dev libssl-dev gperf php cmake clang-6.0 libc++-dev libc++abi-dev
git clone https://github.com/tdlib/td.git
git checkout v1.5.0
cd td
rm -rf build
mkdir build
cd build
export CXXFLAGS="-stdlib=libc++"
CC=/usr/bin/clang-6.0 CXX=/usr/bin/clang++-6.0 cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=../tdlib -DCMAKE_AR=/usr/bin/llvm-ar-6.0 -DCMAKE_NM=/usr/bin/llvm-nm-6.0 -DCMAKE_OBJDUMP=/usr/bin/llvm-objdump-6.0 -DCMAKE_RANLIB=/usr/bin/llvm-ranlib-6.0 ..
cmake --build . --target prepare_cross_compiling
cd ..
php SplitSource.php
cd build
cmake --build . --target install
cd ..
php SplitSource.php --undo
cd ..
ln -s td/tdlib/lib/libtdjson.so.1.5.4 libtdjson.so.1.5.4
