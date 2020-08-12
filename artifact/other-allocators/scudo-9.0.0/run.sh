#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04/lib/clang/9.0.0/lib/linux/libclang_rt.scudo-x86_64.so

if [ ! -e $SO_FILE ]; then
  wget http://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
  tar -xvf clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
