#!/bin/bash

. ../common.sh

case "$1" in
  UBS) # WF, AC, Small
    make_input
    $AFL_FUZZ -i input -o output-$1 -- $DRIVER \
      -a 8:0:16:32 -l 128 -u 1016 \
      -v OVERFLOW -v OFF_BY_ONE_NULL -v OFF_BY_ONE \
      -v DOUBLE_FREE -v ARBITRARY_FREE \
      -e OVERLAP \
      -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
      -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
      @@
    ;;

  HUE) # O1, AC, Small
    make_input
    $AFL_FUZZ -i input -o output-$1 -- $DRIVER \
      -a 8:0:16:32 -l 128 -u 1016 \
      -v OVERFLOW \
      -v WRITE_AFTER_FREE -v DOUBLE_FREE -v ARBITRARY_FREE \
      -e OVERLAP \
      -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
      -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
      @@
    ;;

  OCS) # OV, OC, Small
    make_input
    $AFL_FUZZ -i input -o output-$1 -- $DRIVER \
      -a 8:0:16:32 -l 128 -u 1016 \
      -v OFF_BY_ONE_NULL -v OFF_BY_ONE \
      -v WRITE_AFTER_FREE -v DOUBLE_FREE -v ARBITRARY_FREE \
      -e OVERLAP \
      -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
      -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
      @@
    ;;

  UDF) # DF, OC, Small
    make_input
    $AFL_FUZZ -i input -o output-$1 -- $DRIVER \
      -a 8:0:16:32 -l 128 -u 1016 \
      -v OVERFLOW -v OFF_BY_ONE_NULL -v OFF_BY_ONE \
      -v WRITE_AFTER_FREE -v ARBITRARY_FREE \
      -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER \
      -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER \
      -e ALLOC_IN_CONTAINER -e ALLOC_IN_BUFFER \
      @@
    ;;

  *)
    echo "Usage: $(basename "$0") <technique>"
    echo ''
    echo 'Available techniques:'
    echo '  UBS: Unsorted bin into stack'
    echo '  HUE: House of unsorted einherjar'
    echo '  UDF: Unaligned double free'
    echo '  OCS: Overlapping small chunks'
    ;;
esac
