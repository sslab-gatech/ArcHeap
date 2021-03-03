#!/bin/bash
sudo bash -c "echo core >/proc/sys/kernel/core_pattern"
sudo bash -c "cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor"

