#!/usr/bin/env python3
"""Open the GA100 fuse-data write path (FUSEWDATA_PLM) -- enable step 2.

Writes 0 to OPT_SECURE_FUSE_WDATA_WR_SECURE (0x82048C), which opens
FUSEWDATA_PLM (0x8200F4) to 0xFFFFFFFF so the host CAN later write fuse data.

This is a VOLATILE configuration-register write. It does NOT burn any fuse,
does NOT write FUSEWDATA / FUSEADDR / FUSECTRL, and issues no fuse command.
Nothing permanent happens; a power-cycle reverts it. The actual FF burn is a
separate, later step.

Prereqs: DSOV=0 and EN_SW_OVERRIDE=1 (the glitched + enabled state).

Run on the GPU host:
  sudo python3 open_wdata_plm.py --bdf 0000:01:00.0
  sudo python3 open_wdata_plm.py --bdf 0000:01:00.0 --read-only
"""
import argparse
import json
import mmap
import os
import struct
import sys

DSOV = 0x00820084
EN_SW_OVERRIDE = 0x00820040
WDATA_WR_SECURE = 0x0082048C
FUSEWDATA_PLM = 0x008200F4
MAP_BYTES = 0x822000


def run(bdf, read_only):
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
        en = rd(EN_SW_OVERRIDE)
        wr_before = rd(WDATA_WR_SECURE)
        plm_before = rd(FUSEWDATA_PLM)
        out = {"bdf": bdf, "dsov": dsov, "en_sw_override": en,
               "wdata_wr_secure_before": "0x%08X" % wr_before,
               "fusewdata_plm_before": "0x%08X" % plm_before,
               "read_only": read_only}
        if not read_only:
            if dsov != 0:
                out["warning"] = "DSOV != 0; write likely will not stick (re-glitch first)"
            # The ONLY write: open the fuse-data privilege mask. No fuse command.
            struct.pack_into("<I", mm, WDATA_WR_SECURE, 0)
            wr_after = rd(WDATA_WR_SECURE)
            plm_after = rd(FUSEWDATA_PLM)
            out["wdata_wr_secure_after"] = "0x%08X" % wr_after
            out["fusewdata_plm_after"] = "0x%08X" % plm_after
            out["opened"] = (plm_after == 0xFFFFFFFF)
            out["note"] = ("FUSEWDATA_PLM OPEN - host fuse-data writes permitted "
                           "(no fuse burned)" if out["opened"]
                           else "PLM did NOT open - check DSOV / EN_SW_OVERRIDE")
        return out
    finally:
        mm.close()
        os.close(fd)


def main():
    ap = argparse.ArgumentParser(description="Open GA100 FUSEWDATA_PLM (no fuse burn)")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--read-only", action="store_true")
    args = ap.parse_args()
    if sys.platform != "linux":
        print(json.dumps({"error": "Requires Linux (sysfs BAR0)"}))
        return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"}))
        return 2
    try:
        out = run(args.bdf, args.read_only)
    except Exception as exc:
        print(json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)}))
        return 2
    print(json.dumps(out, indent=2))
    return 0 if (args.read_only or out.get("opened")) else 1


if __name__ == "__main__":
    sys.exit(main())
