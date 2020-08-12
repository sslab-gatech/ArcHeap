FROM ubuntu:16.04

ADD . /src
WORKDIR /src

RUN apt update
RUN apt install -y sudo

RUN ./install_dependencies.sh
RUN ./build.sh
