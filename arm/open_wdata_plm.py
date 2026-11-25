#!/usr/bin/env python3
"""Open the GA100 fuse-data write path (FUSEWDATA_PLM) -- enable step 2.

Writes 0 to OPT_SECURE_FUSE_WDATA_WR_SECURE (0x82048C) using a single aligned
32-bit store, which opens FUSEWDATA_PLM (0x8200F4) to 0xFFFFFFFF so the host
CAN later write fuse data.

This is a VOLATILE configuration-register write. It does NOT burn any fuse,
does NOT write FUSEWDATA / FUSEADDR / FUSECTRL, and issues no fuse command.
Refuses to write unless FUSECTRL is IDLE, GFW (0x118234) low byte is 0xFF,
DSOV == 0, and EN_SW_OVERRIDE == 1.

Run on the GPU host:
  sudo python3 arm/open_wdata_plm.py --bdf 0000:01:00.0
  sudo python3 arm/open_wdata_plm.py --bdf 0000:01:00.0 --read-only
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
    FUSEWDATA_PLM,
    WDATA_WR_SECURE,
)


def run_with_bar(bar, bdf, read_only):
    health = bar.check_health_first(require_idle=True, require_gfw=True)
    dsov = bar.rd_checked(DSOV, "DSOV")
    en = bar.rd_checked(EN_SW_OVERRIDE, "EN_SW_OVERRIDE")
    wr_before = bar.rd_checked(WDATA_WR_SECURE, "WDATA_WR_SECURE")
    plm_before = bar.rd_checked(FUSEWDATA_PLM, "FUSEWDATA_PLM", allow_all_ones=True)
    out = {
        "bdf": bdf,
        "fusectrl": "0x%08X" % health["fusectrl"],
        "boot0": "0x%08X" % health["boot0"],
        "gfw": "0x%08X" % health["gfw"],
        "dsov": dsov,
        "en_sw_override": en,
        "wdata_wr_secure_before": "0x%08X" % wr_before,
        "fusewdata_plm_before": "0x%08X" % plm_before,
        "read_only": read_only,
    }
    if not read_only:
        if dsov != 0:
            out["opened"] = False
            out["note"] = "ABORT: DSOV != 0; refused to write WDATA_WR_SECURE"
            return out
        if (en & 1) != 1:
            out["opened"] = False
            out["note"] = "ABORT: EN_SW_OVERRIDE != 1; run sw_override.py first"
            return out
        # The ONLY write: single aligned 32-bit store to open fuse-data PLM.
        bar.wr(WDATA_WR_SECURE, 0)
        wr_after = bar.rd_checked(WDATA_WR_SECURE, "WDATA_WR_SECURE")
        plm_after = bar.rd_checked(FUSEWDATA_PLM, "FUSEWDATA_PLM", allow_all_ones=True)
        out["wdata_wr_secure_after"] = "0x%08X" % wr_after
        out["fusewdata_plm_after"] = "0x%08X" % plm_after
        out["opened"] = (wr_after == 0 and plm_after == 0xFFFFFFFF)
        out["note"] = (
            "FUSEWDATA_PLM OPEN - host fuse-data writes permitted (no fuse burned)"
            if out["opened"]
            else "PLM did NOT open or WDATA_WR_SECURE != 0 - check DSOV / EN_SW_OVERRIDE"
        )
    return out


def run(bdf, read_only):
    bar = Bar0(bdf, read_only=read_only)
    try:
        return run_with_bar(bar, bdf, read_only)
    finally:
        bar.close()


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
    except Bar0Abort as exc:
        print(json.dumps({"error": "Bar0Abort: %s" % exc}))
        return 1
    except Exception as exc:
        print(json.dumps({"error": "%s: %s" % (type(exc).__name__, exc)}))
        return 2
    print(json.dumps(out, indent=2))
    return 0 if (args.read_only or out.get("opened")) else 1


if __name__ == "__main__":
    sys.exit(main())
