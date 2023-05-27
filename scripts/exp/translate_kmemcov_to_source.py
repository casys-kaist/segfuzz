#!/usr/bin/env python
"""Simple script to translate the output of kmemcov (obtained from
kmemcov_test.c) to source lines."""

import os


def main():
    import argparse

    VMLINUX = os.path.join(os.environ["KERNEL_X86_64"], "vmlinux")

    parser = argparse.ArgumentParser(
        description="Translate kmemcov outputs to source lines"
    )
    parser.add_argument("--vmlinux", action="store", default=VMLINUX)
    parser.add_argument("output", action="store", default="")
    args = parser.parse_args()

    import subprocess

    cutted = subprocess.check_output(
        "cat {} | cut -f1 -d ' '".format(args.output), shell=True
    )
    lines = cutted.decode("utf-8").split("\n")

    addr2line_args = ["addr2line", "-e", args.vmlinux]
    for line in lines:
        if line.startswith("0xffffffff"):
            addr = int(line, 16) - 5
            addr2line_args.append(hex(addr)[2:])
        else:
            addr2line_args.append(line)

    trace = subprocess.check_output(addr2line_args)
    print(trace.decode("utf-8"))


if __name__ == "__main__":
    main()
