#!/usr/bin/env python3
"""Enable/disable GA100 software override -- EN_SW_OVERRIDE (0x00820040).

A SINGLE volatile register write with read-back verification. This is NOT a
fuse burn and touches nothing else. The write only sticks when the card is in
a DSOV=0 (glitched) state; if DSOV=1 the read-back stays 0 and works=False.

Run on the GPU host:
  sudo python3 sw_override.py --bdf 0000:01:00.0            # write 1, verify
  sudo python3 sw_override.py --bdf 0000:01:00.0 --value 0  # disable
  sudo python3 sw_override.py --bdf 0000:01:00.0 --read-only
"""
import argparse
import json
import mmap
import os
import struct
import sys

EN_SW_OVERRIDE = 0x00820040
DSOV = 0x00820084
MAP_BYTES = 0x822000


def run(bdf, value, read_only):
    path = "/sys/bus/pci/devices/%s/resource0" % bdf
    fd = os.open(path, os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
    try:
        mm = mmap.mmap(fd, MAP_BYTES, flags=mmap.MAP_SHARED,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE)
    except BaseException:
        os.close(fd)
        raise
    try:
        rd = lambda o: struct.unpack_from("<I", mm, o)[0]
        dsov = rd(DSOV)
        before = rd(EN_SW_OVERRIDE)
        out = {"bdf": bdf, "dsov": dsov, "before": "0x%08X" % before,
               "requested": value, "read_only": read_only}
        if not read_only:
            struct.pack_into("<I", mm, EN_SW_OVERRIDE, value & 0xFFFFFFFF)
            after = rd(EN_SW_OVERRIDE)
            out["after"] = "0x%08X" % after
            out["works"] = (after == value)
            out["note"] = ("override ENABLED" if after == 1 and value == 1
                           else "override disabled" if after == 0
                           else "write did NOT stick (DSOV must be 0)")
        return out
    finally:
        mm.close()
        os.close(fd)


def main():
    ap = argparse.ArgumentParser(description="GA100 EN_SW_OVERRIDE write + verify")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--value", type=int, default=1, choices=(0, 1))
    ap.add_argument("--read-only", action="store_true")
    args = ap.parse_args()
    if sys.platform != "linux":
        print(json.dumps({"error": "Requires Linux (sysfs BAR0)"}))
        return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"}))
        return 2
    try:
        out = run(args.bdf, args.value, args.read_only)
    except Exception as exc:
        print(json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)}))
        return 2
    print(json.dumps(out, indent=2))
    return 0 if (args.read_only or out.get("works")) else 1


if __name__ == "__main__":
    sys.exit(main())
