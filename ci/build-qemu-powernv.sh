#!/bin/bash
set -e
set -vx

git clone --depth=1 https://github.com/qemu/qemu.git
cd qemu
git submodule update --init dtc
export CC="ccache gcc"
export CXX="ccache g++"
./configure --target-list=ppc64-softmmu --disable-werror
make -j $(grep -c processor /proc/cpuinfo)
