#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/libdlmalloc.so

if [ ! -f $SO_FILE ]; then
  wget http://gee.cs.oswego.edu/pub/misc/malloc-2.7.2.c
  gcc -c -fpic malloc-2.7.2.c
  gcc -shared -o libdlmalloc.so malloc-2.7.2.o

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
