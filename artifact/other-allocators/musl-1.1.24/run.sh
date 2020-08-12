#!/bin/bash

source ../../common.sh

MUSL_GCC=$(pwd)/musl-1.1.24/obj/musl-gcc

if [ ! -e $MUSL_GCC ]; then
  wget https://www.musl-libc.org/releases/musl-1.1.24.tar.gz
  tar -zxvf musl-1.1.24.tar.gz

  pushd musl-1.1.24
  ./configure
  make
  sudo make install
  popd

  make_input
fi

REALGCC=$AFL_GCC $MUSL_GCC -o ./driver-fuzz $DRIVER_ROOT/driver.c
$MUSL_GCC -o ./driver $DRIVER_ROOT/driver.c

unset AFL_PRELOAD
run_all ./driver-fuzz
