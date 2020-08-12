#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/mesh/libmesh.so

if [ ! -e $SO_FILE ]; then
  git clone --recurse-submodules https://github.com/plasma-umass/mesh
  pushd mesh
  git checkout a49b6134
  ./configure
  make
  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
