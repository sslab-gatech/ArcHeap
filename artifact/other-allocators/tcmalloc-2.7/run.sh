#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/gperftools/build/.libs/libtcmalloc.so


if [ ! -e $SO_FILE ]; then
  git clone git@github.com:gperftools/gperftools.git
  pushd gperftools
  git checkout gperftools-2.7
  ./autogen.sh
  mkdir build
  cd build
  ../configure
  make -j$(nproc)
  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
