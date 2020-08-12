#!/bin/bash

source ../../common.sh

MUSL_GCC=$(pwd)/musl-1.1.9/tools/musl-gcc

if [ ! -e $MUSL_GCC ]; then
  wget https://www.musl-libc.org/releases/musl-1.1.9.tar.gz
  tar -zxvf musl-1.1.9.tar.gz

  pushd musl-1.1.9
  ./configure
  make
  make tools/musl-gcc
  sudo make install
  popd

  make_input
fi

REALGCC=$AFL_GCC $MUSL_GCC -o ./driver-fuzz $DRIVER_ROOT/driver.c
$MUSL_GCC -o ./driver $DRIVER_ROOT/driver.c

unset AFL_PRELOAD
run_all ./driver-fuzz
