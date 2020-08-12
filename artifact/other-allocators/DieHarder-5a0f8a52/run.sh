#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/DieHard/src/dieharder.so
if [ ! -e $SO_FILE ]; then
  git clone --recursive https://github.com/emeryberger/DieHard
  pushd DieHard/src
  git checkout 5a0f8a5
  TARGET=dieharder make linux-gcc-x86-64
  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
