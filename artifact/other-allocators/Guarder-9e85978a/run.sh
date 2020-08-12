#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/Guarder/libguarder.so

if [ ! -e $SO_FILE ]; then
  git clone git@github.com:UTSASRG/Guarder.git
  pushd Guarder
  git checkout 9e85978a
  make
  popd

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
