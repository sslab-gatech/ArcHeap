#!/usr/bin/env python2

import argparse
import logging
import os
import re
import subprocess
import signal
import shutil
import tempfile

import minimize

RUN_SH ="""#!/bin/bash
if [ $# -eq 0 ]
    then
        echo "No arguments supplied"
        exit
fi
{0} $1 $1.min
"""

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-abort", action='store_true')
    p.add_argument('afl_dir')
    p.add_argument('output_dir')
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()

    logging.basicConfig(level=logging.DEBUG)

    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)

    # Read fuzzer_stats to find cmd
    fuzzer_stats = open(os.path.join(args.afl_dir, "fuzzer_stats")).read()
    command_line = fuzzer_stats.split("\n")[-2].replace("driver-fuzz", "driver")
    cmd = re.findall(r"[^\s]*driver.*", command_line)[0].split(" ")
    cmd[0] = os.path.abspath(cmd[0])

    run_script = os.path.join(args.output_dir, "run.sh")
    with open(run_script, "w") as f:
        f.write(RUN_SH.format(' '.join(cmd[:-1])))
    os.chmod(run_script, 0775)

    minimals = {}
    crash_dir = os.path.join(args.afl_dir, "crashes")
    minimizer = minimize.Minimizer(cmd, args.abort)
    for name in sorted(os.listdir(crash_dir)):
        if name in ["README.txt"]:
            continue
        path = os.path.join(crash_dir, name)
        action_map_file = os.path.join(args.output_dir, name + ".min")
        out_html = os.path.join(args.output_dir, name + ".html")
        log_file = os.path.join(args.output_dir, name + ".log")
        try:
            nactions, event, vuln = minimizer.minimize(path, action_map_file, out_html, log_file)
        except AssertionError:
            continue
        except UnicodeDecodeError:
            continue
        except OSError:
            # sometimes OOM happens..
            continue

        if nactions is None:
            continue
        key = event.decode("utf-8") + ":" + vuln.decode("utf-8")

        if not key in minimals:
            minimals[key] = (2**32, "initial_file")
        min_nactions, _ = minimals[key]
        if min_nactions > nactions:
            minimals[key] = (nactions, name)

        shutil.copy(path, os.path.join(args.output_dir, name))

        # Save raw log file
        raw_log_file = os.path.join(args.output_dir, name + ".rawlog")
        stderr, _ = minimizer.run_driver(path)
        with open(raw_log_file, "wb") as f:
            f.write(stderr)

    with open(os.path.join(args.output_dir, "minimal.info"), "w") as f:
        for k, v in minimals.items():
            f.write("%s: %s (%d)\n" % (k, v[1], v[0]))
