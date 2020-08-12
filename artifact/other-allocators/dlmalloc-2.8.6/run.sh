#!/bin/bash

source ../../common.sh

SO_FILE=$(pwd)/libdlmalloc.so
if [ ! -f $SO_FILE ]; then
  wget ftp://gee.cs.oswego.edu/pub/misc/malloc.c
	gcc -c -Wall -Werror -fpic malloc.c
	gcc -shared -o libdlmalloc.so malloc.o

  make_input
fi

AFL_PRELOAD=$SO_FILE run_all
