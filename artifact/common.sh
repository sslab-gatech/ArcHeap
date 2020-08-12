DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT=$DIR/..

AFL_ROOT=$ROOT/tool/afl-2.52b
AFL_FUZZ=$AFL_ROOT/afl-fuzz
AFL_GCC=$AFL_ROOT/afl-gcc

DRIVER_ROOT=$ROOT/driver
DRIVER=$DRIVER_ROOT/driver-fuzz

function make_input() {
  if [ ! -e input ]; then
    mkdir -p input
    echo "AAAA" > input/seed
  fi
}

function run_all() {
  if [ "$#" -eq 1 ]; then
    APP=$1
  else
    APP=$DRIVER
  fi

  export AFL_NO_UI=1
  $AFL_FUZZ -m none -i input -o output-OC -- $APP \
    -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
    -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
    -e ALLOC_IN_CONTAINER -e ALLOC_IN_BUFFER \
    @@ &

  $AFL_FUZZ -m none -i input -o output-AC -- $APP \
    -e OVERLAP \
    -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
    -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
    @@ &

  $AFL_FUZZ -m none -i input -o output-RW -- $APP \
    -e OVERLAP \
    -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
    -e ALLOC_IN_CONTAINER -e ALLOC_IN_BUFFER \
    @@ &

  $AFL_FUZZ -m none -i input -o output-AW -- $APP \
    -e OVERLAP \
    -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
    -e ALLOC_IN_CONTAINER -e ALLOC_IN_BUFFER \
    @@
}
