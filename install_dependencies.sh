#!/bin/bash

set -x

sudo apt update
sudo apt install -y build-essential git wget python3 ltrace

sudo bash -c "echo core >/proc/sys/kernel/core_pattern"
sudo bash -c "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor"

