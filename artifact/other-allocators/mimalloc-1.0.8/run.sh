#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/mimalloc/out/release/libmimalloc.so

if [ ! -e $SO_FILE ]; then
  git clone git@github.com:microsoft/mimalloc.git

  pushd mimalloc

  git checkout v1.0.8
  mkdir -p out/release
  cd out/release
  cmake ../..
  make

  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
