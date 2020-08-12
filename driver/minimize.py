#!/usr/bin/env python3
import argparse
import copy
import logging
import os
import re
import subprocess
import shutil
import time
import tempfile
import signal

BUF_MAX = 4096

l = logging.getLogger('heap_exp.minimize')

def get_driver_exe():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "driver"))

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-abort", action='store_true')
    p.add_argument("-html", default=None)
    p.add_argument("action_map_file")
    p.add_argument("cmd", nargs="+")
    return p.parse_args()

class Minimizer(object):
    def __init__(self, cmd, abort=False):
        self.cmd = cmd[:-1]
        assert(cmd[-1] == "@@")
        self.abort = abort

    @property
    def crash_signals(self):
        sig = signal.SIGABRT if self.abort else signal.SIGUSR2
        return [-sig, 128 + sig]

    def run_driver(self, input_file, action_map_file=None):
        env = copy.copy(os.environ)
        env["LIBC_FATAL_STDERR_"] = "1"
        if "AFL_PRELOAD" in env:
            env["LD_PRELOAD"] = env["AFL_PRELOAD"]

        stdout = open(os.devnull, "wb")
        stderr = subprocess.PIPE

        cmd = ["timeout", "-k", "1", "5"] + self.cmd + [input_file]
        if action_map_file:
            cmd += [action_map_file]

        p = subprocess.Popen(
                cmd,
                env=env,
                stdout=stdout, stderr=stderr)
        _, stderr = p.communicate()
        return stderr.decode('utf-8'), p.wait()

    def check_crash(self, input_file):
        _, retcode = self.run_driver(input_file)
        return retcode in self.crash_signals

    def get_event(self, input_file, action_map_file=None):
        stderr, _ = self.run_driver(input_file, action_map_file)
        events = re.findall(r"(EVENT_.*) is detected", stderr)
        if not events:
            return None
        assert(len(events) == 1)
        return events[0]

    def get_num_actions(self, input_file, action_map_file=None):
        stderr, _ = self.run_driver(input_file, action_map_file)
        nactions = re.findall(r"The number of actions: (\d+)", stderr)
        assert(len(nactions) == 1)
        return int(nactions[0])

    def get_vuln(self, input_file, action_map_file=None):
        stderr, _ = self.run_driver(input_file, action_map_file)
        vuln = re.findall(r"\[VULN\] (.*)", stderr)
        if not vuln:
            return "NO_VULN"

        return vuln[0]

    def minimize(self, crash_file, action_map_file, out_html=None, log_file=None,
            timeout=5 * 60):
        # Check if it is really crash file
        if not self.check_crash(crash_file):
            l.info("No crash file: %s" % crash_file)
            return None, None, None

        l.info("Start to minimize: %s" % crash_file)

        event = self.get_event(crash_file)
        nactions = self.get_num_actions(crash_file)

        if not nactions:
            l.info("No crash file: %s" % crash_file)
            return None, None, None

        action_map = bytearray(b"\x00" * nactions)

        start_time = time.time()
        for i in range(len(action_map)):
            action_map[i] = 0xff # Disable it
            with open(action_map_file, "wb") as f:
                f.write(action_map)
            new_event = self.get_event(crash_file, action_map_file)
            if event != new_event:
                action_map[i] = 0x00
                l.info("Need %dth action" % i)
            if time.time() - start_time > timeout:
                break

        with open(action_map_file, "wb") as f:
            f.write(action_map)

        villoc = os.path.join(os.path.dirname(__file__), "../tool/villoc/villoc.py")

        # Generate out.html
        cmd = self.cmd + [crash_file, action_map_file]
        if out_html:
            os.system('/bin/bash -c "ltrace %s |& %s - %s 2>/dev/null"'
                    % (' '.join(cmd), villoc, out_html))

        if log_file:
            p = subprocess.Popen(cmd,
                    stdout=open(os.devnull, "wb"),
                    stderr=open(log_file, "wb"))
            p.wait()

        nactions = self.get_num_actions(crash_file, action_map_file)
        event = self.get_event(crash_file, action_map_file)
        vuln = self.get_vuln(crash_file, action_map_file)

        if any([not bool(b) for b in [nactions, event, vuln]]):
            return None, None, None

        return nactions, event, vuln

def write_to_tmp(data, tmp):
    with open(tmp, "wb") as f:
        f.write(data)

def shrink(data, tmp, abort):
    stdout, stderr, _ = run_driver(data, tmp)

    pat = re.compile(r".*\[CMD\] beg=(\d+), end=(\d+)")

    for l in reversed(stderr.splitlines()):
        m = pat.match(l)
        if m:
            beg, end = map(int, m.groups())
            new_data = data[:beg] + data[end:]
            if check(new_data, tmp, abort):
                return new_data, beg, end
    return [None, None, None]


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    args = parse_args()

    cmd = copy.copy(args.cmd)
    crash_file = cmd[-1]
    cmd[-1] = "@@"
    minimizer = Minimizer(cmd, args.abort)
    minimizer.minimize(crash_file, args.action_map_file, args.html)

    # Run to show the minimized one
    import sys
    sys.stderr.write("\n")
    os.system(" ".join(args.cmd[:-1] + [crash_file, args.action_map_file]))
