#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/mimalloc/out/secure/libmimalloc-secure.so

if [ ! -e $SO_FILE ]; then
  git clone git@github.com:microsoft/mimalloc.git

  pushd mimalloc

  git checkout v1.0.8
  mkdir -p out/secure
  cd out/secure
  cmake -DMI_SECURE=ON ../..
  make

  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
