#!/usr/bin/env python


def sanitize_crash(crash):
    if crash.find("SYZFAIL") != -1:
        return False
    elif crash.find("fbcon: Driver") != -1:
        return False
    elif crash.find("lost connection") != -1:
        return False
    elif crash.find("no output") != -1:
        return False
    return True


def parse(filename):
    import datetime
    import re
    import time

    with open(filename) as f:
        lines = f.readlines()

    crashes = set()
    TAG = "[MANAGER]"

    prevts = 0
    res = {}
    g = (0, 0, 0, 0, 0, 0)
    rec = (0, 0, 0, 0, 0, 0, 0)
    for line in lines:
        idx = line.find(TAG)
        if idx == -1:
            continue
        line = line[idx + len(TAG) :].strip()
        toks = line.split(" ", 2)
        time_str = " ".join(toks[:2])
        ts = time.mktime(
            datetime.datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S").timetuple()
        )

        line = toks[2]
        if line.find("VMs") == -1:
            ts = prevts
            CRASH = "crash: "
            idx = line.find(CRASH)
            if idx != -1:
                crash = line[idx + len(CRASH) :]
                if sanitize_crash(crash) and crash not in crashes:
                    crashes.add(crash)
            else:
                continue
            rec = g + (len(crashes),)
        else:
            match = re.search(
                "executed ([0-9]+), cover ([0-9]+), signal ([0-9]+)/([0-9]+), interleaving ([0-9]+)/([0-9]+)",
                line,
            )
            g = match.group(1, 2, 3, 4, 5, 6)
            rec = g + (len(crashes),)

        res[ts] = rec
        prevts = ts

    for ts in sorted(res, key=lambda ts: int(ts)):
        print(ts, ", ".join(str(f) for f in res[ts]), sep=", ")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Parsing manager outputs to generate statistics"
    )
    parser.add_argument(
        "input", action="store", help="a file containing manager output"
    )
    args = parser.parse_args()
    filename = args.input
    print("Parsing {}".format(filename))

    parse(filename)


if __name__ == "__main__":
    main()
