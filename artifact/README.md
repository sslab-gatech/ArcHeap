# Artifact for ArcHeap

## Getting started

First of all, we need to specify an initial seed for ArcHeap, which relies on
[AFL](https://github.com/google/AFL). According to our experience, choice of
this seed is not important since ArcHeap will eventually converge. So, we will
use a dumb seed (e.g, AAAA).

```bash
$ mkdir input
$ echo "AAAA" > input/seed
```

After specifying the seed, we can run ArcHeap as same with AFL. If we don't
specify any allocator, ArcHeap will use a system allocator by default (e.g.,
ptmalloc2 in Linux).

```bash
# Run ArcHeap without any model for a system allocator
$ ../tool/afl-2.52b/afl-fuzz -i input -o output ../driver/driver-fuzz @@
```

Unfortunately, if we run ArcHeap without any model, it will converge to random,
trivial exploit techniques. To discover more specific techniques, ArcHeap
supports several model specifications, which can be defined using arguments of
`driver-fuzz`. You can check available model specifications from its help
message. It is worth noting that ArcHeap's specifications are exclusive, i.e.,
ArcHeap limits capabilities with specifications and its default mode allows
every action. Here is an example to specify the model.

```bash
$ ../driver/driver-fuzz -h
Usage: ../driver/driver-fuzz [OPTION]... FILE [MAPFILE]
  -c <cap>: Disable a capability
     <cap>:= HEAP_ADDR | CONTAINER_ADDR | BUFFER_ADDR | DEALLOC | HEAP_WRITE | BUFFER_WRITE
  -v <vuln>: Disable a vulnerbility
     <vuln>:= OVERFLOW | OFF_BY_ONE_NULL | OFF_BY_ONE | WRITE_AFTER_FREE | DOUBLE_FREE | ARBITRARY_FREE
  -e <event>: Disable an event
     <event>:= OVERLAP | RESTRICTED_WRITE_IN_CONTAINER | RESTRICTED_WRITE_IN_BUFFER | ARBITRARY_WRITE_IN_CONTAINER | ARBITRARY_WRITE_IN_BUFFER | ALLOC_IN_CONTAINER | ALLOC_IN_BUFFER
  -u <ub>: Set upper bound of allocation
  -l <lb>: Set lower bound of allocation
  -s <list-of-sizes>: Set allocations sizes (e.g., 1,2,3)
  -a <header>:<footer>:<round>:<minsz>: Set information for allocator
    e.g. For ptmalloc in 64-bit, -a 8:0:16:32
  -h: Display this help and exit

# Discover a technique rendering an arbitrary chunk with double free
# i.e., no DOUBLE_FREE in vulnerbilities, no ALLOC_IN_CONTAINER and ALLOC_IN_BUFFER in events
$ SPEC="-a 8:0:16:32 \
	-v OVERFLOW -v OFF_BY_ONE_NULL -v OFF_BY_ONE -v WRITE_AFTER_FREE -v ARBITRARY_FREE \
	-e OVERLAP -e RESTRICTED_WRITE_IN_CONTAINER -e RESTRICTED_WRITE_IN_BUFFER -e ARBITRARY_WRITE_IN_CONTAINER -e ARBITRARY_WRITE_IN_BUFFER"
$ eval "../tool/afl-2.52b/afl-fuzz -i input -o output ../driver/driver-fuzz $SPEC @@"
```

If AFL finds a crash, the `driver-fuzz` can be used for generating PoC,
which is C code that triggers the discovered technique. In most of cases, the C
code is compilable, but a user might need to fix a trivial compilation error
because of a trailing error message from an allocator. The same specifications
that are used for discovering should be provided for making valid PoC.

```bash
# Generate PoC code
$ eval "../driver/driver-fuzz $SPEC ./output/crashes/id:000000* 2>&1|tee poc.c"

# Compile and validate the PoC
$ gcc -o poc poc.c
$ ./poc
```

Because of ArcHeap's random search, the PoC file could have irrelevant code.
This can be minimized using delta debugging. In particular, ArcHeap makes a
bitmap file that represents whether each action is essential to trigger this
exploit technique. This also can be done for all crashes in the output
directory. In this case, ArcHeap also provides a visual representation of heap
layout using [villoc](https://github.com/wapiflapi/villoc) for better
understanding of found techniques.

```bash
# Make a bitmap for minimizing PoC using delta debugging
$ eval "../driver/minimize.py bitmap_file -- ../driver/driver-fuzz $SPEC ./output/crashes/id:000000*"

# Generate minimal PoC code using the bitmap and validate
$ eval " ../driver/driver-fuzz $SPEC ./output/crashes/id:000000* bitmap_file 2>&1|tee poc-min.c"
$ gcc -o poc-min poc-min.c
$ ./poc-min

# Minimize all crashes in the output directory
$ ../driver/minimize_all.py output minimized_output

# Check minimized PoC and heap layout from villoc
$ cat minimized_output/id:000000*.log
$ open minimized_output/id:000000*.html
```

ArcHeap supports discovering techniques in other allocators using `LD_PRELOAD`.
To this end, a shared library for the allocator should be defined in the
`AFL_PRELOAD`, which is `LD_PRELOAD` for AFL, in a discovering and a
minimization phase. When validating PoC, the allocator should be specified
using `LD_PRELOAD`. 

```bash
# Repeat the same procedures in a non-system allocator that is specified as $(SO_FILE)
$ eval "AFL_PRELOAD=$(SO_FILE) ../tool/afl-2.52b/afl-fuzz -i input -o output ../driver/driver-fuzz $SPEC @@"
$ eval "AFL_PRELOAD=$(SO_FILE) ../driver/minimize.py bitmap_file -- ../driver/driver-fuzz $SPEC ./output/crashes/id:000000*"
$ eval "LD_PRELOAD=$(SO_FILE) ../driver/driver-fuzz $SPEC ./output/crashes/id:000000* bitmap_file 2>&1|tee poc-min.c"
$ gcc -o poc-min poc-min.c
$ LD_PRELOAD=$(SO_FILE) ./poc-min
```

## 7.1 New Heap Exploitation Techniques

This section discusses how to find new exploit techniques in ptmalloc2, which
is described in Section 7.1 in our paper. For convenient evaluation, we provide
a bash script (`run.sh`) that encodes every model that we used. Note that we
omit `fast bin into other bin` because ArcHeap usually converges to `fast bin
dup`, whose model is a subset of the previous one's. This issue is also
illustrated in Section 8.1. In the following, we will re-discover `unsorted bin
into stack` using ArcHeap.

```bash
$ cd ptmalloc2-glibc2.23
$ ./run.sh 
Usage: run.sh <technique>

Available techniques:
  UBS: Unsorted bin into stack
  HUE: House of unsorted einherjar
  UDF: Unaligned double free
  OCS: Overlapping small chunks

# Run and wait until ArcHeap discovers crashes
$ ./run.sh UBS

# Check model specifications, which will be called as $SPEC in the following code
$ tail -n 1 output-UBS/fuzzer_stats
# This output will be 'commaond_line:  ... driver-fuzz $SPEC @@'

# Generate PoC (also can be validated and minimized as before)
$ eval "../../driver/driver-fuzz $SPEC ./output/crashes/id:000000*"
```

## 7.2 Different Types of Heap Allocators

This section describes how to use ArcHeap for finding new exploit techniques in
other allocators. Similar to the previous one, we also provide script files
(`other-allocators/*/run.sh`) to run ArcHeap for each allocator with different
events (i.e., impacts of exploitation).  After discovering crashes, we can find
ArcHeap's current model specifications from AFL's `fuzzer_stats` and a shared
library path in `run.sh`.  After properly setting the specifications and the
library, ArcHeap can make valid PoC for this allocator. Here, we will show how
to find an exploit technique in [DieHarder](https://github.com/emeryberger/DieHard)
as an example.

```bash
# Run and wait until ArcHeap discovers crashes
$ cd ./other-allocators/DieHarder-5a0f8a52/
$ ./run.sh

# Check model specifications, which will be called as $SPEC in the following code
$ tail -n 1 output-OC/fuzzer_stats
# This output will be 'commaond_line:  ... driver-fuzz $SPEC @@'

# Generate PoC (also can be validated and minimized as before)
$ eval "LD_PRELOAD=$(pwd)/DieHard/src/dieharder.so ../../../driver/driver-fuzz $SPEC output-OC/crashes/id:000000*"
```

If you have any question, let us know. Thank you!
