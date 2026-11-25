#!/usr/bin/env python3
"""Enable/disable GA100 software override -- EN_SW_OVERRIDE (0x00820040).

A SINGLE aligned 32-bit volatile register write with read-back verification.
This is NOT a fuse burn and touches nothing else. Refuses to write when
DSOV != 0 (for --value 1), when FUSECTRL is not IDLE, when GFW (0x118234) is
not ready (low byte != 0xFF), or on any PRI poison (0xBADxxxxx).

Run on the GPU host:
  sudo python3 arm/sw_override.py --bdf 0000:01:00.0            # write 1, verify
  sudo python3 arm/sw_override.py --bdf 0000:01:00.0 --value 0  # disable
  sudo python3 arm/sw_override.py --bdf 0000:01:00.0 --read-only
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import (  # noqa: E402
    Bar0,
    Bar0Abort,
    DSOV,
    EN_SW_OVERRIDE,
)


def run_with_bar(bar, bdf, value, read_only):
    health = bar.check_health_first(require_idle=True, require_gfw=True)
    dsov = bar.rd_checked(DSOV, "DSOV")
    before = bar.rd_checked(EN_SW_OVERRIDE, "EN_SW_OVERRIDE")
    out = {
        "bdf": bdf,
        "fusectrl": "0x%08X" % health["fusectrl"],
        "boot0": "0x%08X" % health["boot0"],
        "gfw": "0x%08X" % health["gfw"],
        "dsov": dsov,
        "before": "0x%08X" % before,
        "requested": value,
        "read_only": read_only,
    }
    if not read_only:
        if value == 1 and dsov != 0:
            out["works"] = False
            out["note"] = "ABORT: DSOV != 0; refused to write EN_SW_OVERRIDE (not in glitch window)"
            return out
        bar.wr(EN_SW_OVERRIDE, value)
        after = bar.rd_checked(EN_SW_OVERRIDE, "EN_SW_OVERRIDE")
        out["after"] = "0x%08X" % after
        out["works"] = (after == value)
        if value == 1 and after == 1:
            out["note"] = "override ENABLED"
        elif value == 0 and after == 0:
            out["note"] = "override disabled"
        else:
            out["note"] = "write did NOT stick (DSOV must be 0)"
    return out


def run(bdf, value, read_only):
    bar = Bar0(bdf, read_only=read_only)
    try:
        return run_with_bar(bar, bdf, value, read_only)
    finally:
        bar.close()


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
    except Bar0Abort as exc:
        print(json.dumps({"error": "Bar0Abort: %s" % exc}))
        return 1
    except Exception as exc:
        print(json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)}))
        return 2
    print(json.dumps(out, indent=2))
    return 0 if (args.read_only or out.get("works")) else 1


if __name__ == "__main__":
    sys.exit(main())
