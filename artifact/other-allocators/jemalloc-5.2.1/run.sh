#!/bin/bash

source ../../common.sh

if [ ! -e jemalloc ]; then
  git clone https://github.com/jemalloc/jemalloc
  pushd jemalloc
  git checkout 5.2.1
  ./autogen.sh
  make

  chmod +x bin/jemalloc-config
  popd

  make_input
fi

PATH=$PATH:$(pwd)/jemalloc/bin
AFL_PRELOAD=$(jemalloc-config --libdir)/libjemalloc.so.$(jemalloc-config --revision) run_all
