#!/bin/bash

git submodule init
git submodule update

if [ ! -e tool/afl-2.52b ]; then
  pushd tool
  wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz
  tar -zxvf afl-2.52b.tgz
  rm afl-2.52b.tgz
  cd afl-2.52b
  patch < ../afl.patch
  popd
fi

pushd tool/afl-2.52b
make clean
make
popd

pushd driver
make clean
make
popd
