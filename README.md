# ArcHeap: Automatic Techniques to Systematically Discover New Heap Exploitation Primitives

## Environment
- Tested on Ubuntu 16.04 64bit

## Installation
```bash
$ ./install_dependencies.sh
$ ./build.sh
```

## Installation using Docker
```bash
$ docker build -t archeap .
$ docker run -it archeap /bin/bash
```

## How to use
Please check our [artifact](artifact).

## Trophies
- [Overlapping chunks with double free in mimalloc](https://github.com/microsoft/mimalloc/issues/161)
- [Overlapping chunks with double free in DieHarder](https://github.com/emeryberger/DieHard/issues/12)
- [Overlapping chunks with negative size allocation in mesh](https://github.com/plasma-umass/Mesh/issues/62)
- [Arbitrary chunks with overflow in ptmalloc2](https://github.com/shellphish/how2heap/pull/77)
- [Several other techniques](techniques)

## Authors
- Insu Yun (insu@gatech.edu)
- Dhaval Kapil (me@dhavalkapil.com)
- Taesoo Kim (taesoo@gatech.edu)

## Publications
```
@inproceedings{yun:archeap,
  title        = {{Automatic Techniques to Systematically Discover New Heap Exploitation Primitives}},
  author       = {Insu Yun and Dhaval Kapil and Taesoo Kim},
  booktitle    = {Proceedings of the 29th USENIX Security Symposium (Security)},
  month        = aug,
  year         = 2020,
}
```
