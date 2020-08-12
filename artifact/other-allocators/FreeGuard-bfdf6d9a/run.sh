#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/FreeGuard/libfreeguard.so

if [ ! -e $SO_FILE ]; then
  git clone git@github.com:UTSASRG/FreeGuard.git
  pushd FreeGuard
  git checkout bfdf6d9a
  make SSE2RNG=1
  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
