#!/usr/bin/env python3
"""Arm fuse programming after a Goldilocks glitch: FUSECTRL SENSE_CTRL. NO BURN.

Hardened safety guarantees:
  - Single aligned 32-bit BAR0 writes (memoryview cast, never struct.pack_into).
  - Reads FUSECTRL IDLE, BOOT0=GA100, and GFW (0x118234 low byte == 0xFF) first;
    aborts immediately on any PRI poison (0xBADxxxxx), dead BAR0, non-IDLE,
    GFW stall, or timeout — zero extra register reads after any fault.
  - Pure dry-run opens BAR0 O_RDONLY (cannot write hardware).
  - Reads FUSEWDATA as raw 32-bit data (no false poison classification on data).
  - Re-verifies all window prerequisites AFTER human types SENSE before writing.

  sudo python3 arm/arm_sense_ctrl.py --bdf 0000:01:00.0              # dry-run
  sudo python3 arm/arm_sense_ctrl.py --bdf 0000:01:00.0 --confirm    # type SENSE
  sudo python3 arm/arm_sense_ctrl.py --bdf 0000:01:00.0 --clear-sbfe # after sense
"""
import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import (  # noqa: E402
    Bar0,
    Bar0Abort,
    CMD_IDLE,
    CMD_SENSE_CTRL,
    CRC_STATUS,
    DEBUGCTRL,
    DFP,
    DSOV,
    EFP,
    EN_SW_OVERRIDE,
    FUSEADDR,
    FUSECTRL,
    FUSECTRL_PLM,
    FUSEOPT_PLM,
    FUSEWDATA,
    FUSEWDATA_PLM,
    GFW_BOOT,
    RESENSE_DISABLE,
    RWL_BIT,
    SBFE,
    WDATA_WR_SECURE,
    gfw_ready,
    is_idle,
)

PLM_NAMES = {"FUSEWDATA_PLM", "FUSECTRL_PLM", "FUSEOPT_PLM"}
RAW_DATA_NAMES = {"FUSEWDATA"}
WATCH = [
    ("FUSECTRL", FUSECTRL),
    ("GFW_BOOT", GFW_BOOT),
    ("CRC_STATUS", CRC_STATUS),
    ("DSOV", DSOV),
    ("EFP", EFP),
    ("DISABLE_FUSE_PROGRAM", DFP),
    ("SBFE", SBFE),
    ("EN_SW_OVERRIDE", EN_SW_OVERRIDE),
    ("RESENSE_DISABLE", RESENSE_DISABLE),
    ("FUSEWDATA_PLM", FUSEWDATA_PLM),
    ("FUSECTRL_PLM", FUSECTRL_PLM),
    ("FUSEOPT_PLM", FUSEOPT_PLM),
    ("WDATA_WR_SECURE", WDATA_WR_SECURE),
    ("DEBUGCTRL", DEBUGCTRL),
    ("FUSEADDR", FUSEADDR),
    ("FUSEWDATA", FUSEWDATA),
]


def snap(bar):
    """Fail-fast register snapshot: stops immediately on poison, non-IDLE, or GFW stall."""
    out = {}
    for name, off in WATCH:
        if name in RAW_DATA_NAMES:
            val = bar.rd(off)
        else:
            val = bar.rd_checked(off, name, allow_all_ones=(name in PLM_NAMES))
        out[name] = val
        if name == "FUSECTRL" and not is_idle(val):
            raise Bar0Abort("FUSECTRL not IDLE during snapshot: 0x%08X (STOP)" % val)
        if name == "GFW_BOOT" and not gfw_ready(val):
            raise Bar0Abort("GFW_BOOT not ready during snapshot: 0x%08X (STOP)" % val)
    return out


def show(title, s, before=None):
    print(title)
    for name, _ in WATCH:
        mark = ""
        if before is not None and before[name] != s[name]:
            mark = "   <- was 0x%08X" % before[name]
        print("  %-22s 0x%08X%s" % (name, s[name], mark))


def window_checks(s):
    return [
        ("FUSECTRL IDLE", is_idle(s["FUSECTRL"])),
        ("GFW_BOOT low byte 0xFF", gfw_ready(s["GFW_BOOT"])),
        ("CRC_STATUS=0x55", s["CRC_STATUS"] == 0x55),
        ("DSOV=0 (glitch window)", s["DSOV"] == 0),
        ("EFP=0 (pre-sense)", s["EFP"] == 0),
        ("EN_SW_OVERRIDE=1", (s["EN_SW_OVERRIDE"] & 1) == 1),
        ("RESENSE_DISABLE=0", s["RESENSE_DISABLE"] == 0),
        ("DEBUGCTRL.RWL=0", (s["DEBUGCTRL"] & RWL_BIT) == 0),
        ("WDATA_WR_SECURE=0", s["WDATA_WR_SECURE"] == 0),
        ("FUSEWDATA_PLM open (latch)", s["FUSEWDATA_PLM"] == 0xFFFFFFFF),
        ("FUSECTRL_PLM open", s["FUSECTRL_PLM"] == 0xFFFFFFFF),
    ]


def armed_checks(s):
    return [
        ("FUSECTRL IDLE", is_idle(s["FUSECTRL"])),
        ("GFW_BOOT low byte 0xFF", gfw_ready(s["GFW_BOOT"])),
        ("CRC_STATUS=0x55", s["CRC_STATUS"] == 0x55),
        ("DSOV=0", s["DSOV"] == 0),
        ("EFP=1", s["EFP"] == 1),
        ("DEBUGCTRL.RWL=0", (s["DEBUGCTRL"] & RWL_BIT) == 0),
        ("FUSEWDATA_PLM open", s["FUSEWDATA_PLM"] == 0xFFFFFFFF),
        ("FUSECTRL_PLM open", s["FUSECTRL_PLM"] == 0xFFFFFFFF),
    ]


def clear_sbfe(bar):
    bar.check_health_first(require_idle=True, require_gfw=True)
    s = snap(bar)
    show("=== state ===", s)
    if (
        not is_idle(s["FUSECTRL"])
        or not gfw_ready(s["GFW_BOOT"])
        or s["CRC_STATUS"] != 0x55
        or s["DSOV"] != 0
        or s["EFP"] != 1
    ):
        print("ABORT: need IDLE, GFW=0xFF, CRC=0x55, DSOV=0, and EFP=1 before clearing SBFE.")
        return 1
    if s["SBFE"] == 0:
        print("SBFE already 0; nothing to do.")
        return 0
    bar.wr(EN_SW_OVERRIDE, 1)
    if (bar.rd_checked(EN_SW_OVERRIDE, "EN_SW_OVERRIDE") & 1) != 1:
        print("ABORT: EN_SW_OVERRIDE did not stick.")
        return 1
    bar.wr(SBFE, 0)
    rb = bar.rd_checked(SBFE, "SBFE")
    print("SBFE write 0 -> readback 0x%X  %s" % (rb, "OK" if rb == 0 else "FAILED"))
    return 0 if rb == 0 else 1


def execute(bar, confirm=False, do_clear_sbfe=False, input_fn=input, post_sense_sleep=0.01,
            confirm_timeout_s=60.0):
    bar.check_health_first(require_idle=True, require_gfw=True)
    if do_clear_sbfe:
        return clear_sbfe(bar)

    before = snap(bar)
    show("=== before ===", before)
    if before["EFP"] not in (0, 1):
        print("\nABORT: unexpected EFP=0x%08X (expected 0 or 1). Nothing written." % before["EFP"])
        return 1
    if before["EFP"] == 1 and before["DSOV"] == 0:
        ok = True
        print("\n=== already-armed checks ===")
        for name, passed in armed_checks(before):
            print("  [%s] %s" % ("OK" if passed else "FAIL", name))
            ok = ok and passed
        if not ok:
            print("\nABORT: EFP=1/DSOV=0 but remaining arm conditions failed. Do NOT re-sense or burn.")
            return 1
        print("\nEFP=1 and DSOV=0 already: armed. Skipping SENSE_CTRL.")
        if before["SBFE"] != 0:
            print("SBFE=0x%X -> next: --clear-sbfe" % before["SBFE"])
        return 0

    ok = True
    print("\n=== window checks ===")
    for name, passed in window_checks(before):
        print("  [%s] %s" % ("OK" if passed else "FAIL", name))
        ok = ok and passed
    if not ok:
        print("\nABORT: not in a usable glitch window. Nothing written.")
        return 1

    print("\nPlanned writes:")
    print("  FUSEWDATA = 0x00000000, read back == 0   (no-burn latch)")
    print("  FUSECTRL  = 0x0 (IDLE), then 0x3 (SENSE_CTRL); poll IDLE")
    if not confirm:
        print("\nDRY-RUN: nothing written. Add --confirm to issue SENSE_CTRL.")
        return 0
    t_prompt = time.monotonic()
    try:
        resp = input_fn("Type SENSE to issue FUSECTRL=3: ")
    except EOFError:
        resp = ""
    if confirm_timeout_s is not None and (time.monotonic() - t_prompt) > confirm_timeout_s:
        print("ABORT: confirmation expired (> %.0fs). Re-run dry-run; nothing written." % confirm_timeout_s)
        return 1
    if resp.strip() != "SENSE":
        print("ABORT: not confirmed. Nothing written.")
        return 1

    # Re-verify full window state after human confirmation (prevents stale approval).
    bar.check_health_first(require_idle=True, require_gfw=True)
    recheck = snap(bar)
    if not all(passed for _, passed in window_checks(recheck)):
        print("ABORT: window state changed while waiting for confirmation. Nothing written.")
        return 1

    bar.wr(FUSEWDATA, 0)
    wdata_rb = bar.rd(FUSEWDATA)
    if wdata_rb != 0:
        print("ABORT: FUSEWDATA did not read back 0 (0x%08X). No command issued." % wdata_rb)
        return 1

    bar.wr(FUSECTRL, CMD_IDLE)
    bar.wr(FUSECTRL, CMD_SENSE_CTRL)
    # Fail-fast: if poll_idle raises Bar0Abort (timeout or poison), stop immediately
    # with ZERO subsequent register reads.
    bar.poll_idle(2000)
    if post_sense_sleep > 0:
        time.sleep(post_sense_sleep)

    after = snap(bar)
    print()
    show("=== after SENSE_CTRL ===", after, before)
    if after["DSOV"] != 0:
        print("\nWINDOW LOST: DSOV=1 after sense. Nothing burned. Power off, re-glitch.")
        return 1
    if after["CRC_STATUS"] != 0x55:
        print("\nSTOP: CRC_STATUS changed. Do nothing else; save this output.")
        return 1
    if after["EFP"] != 1:
        print("\nSTOP: EFP still 0x%X -- SENSE_CTRL did not arm. Do NOT re-sense." % after["EFP"])
        return 1

    print("\nARMED: DSOV=0, EFP=1.")
    if after["SBFE"] != 0:
        print("SBFE=0x%X -> next: --clear-sbfe" % after["SBFE"])
    print("Then: ff_dump.py (window snapshot), ffcard.py check, ff_burn.py dry-run.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="SENSE_CTRL arm (no burn)")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--confirm", action="store_true", help="issue SENSE_CTRL (else dry-run)")
    ap.add_argument("--clear-sbfe", action="store_true", help="shadow-write SBFE=0 after sense")
    args = ap.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print("Requires Linux + sudo")
        return 2

    read_only = (not args.confirm and not args.clear_sbfe)
    try:
        bar = Bar0(args.bdf, read_only=read_only)
    except Bar0Abort as exc:
        print("STOP: %s" % exc)
        return 1
    try:
        return execute(bar, confirm=args.confirm, do_clear_sbfe=args.clear_sbfe)
    except Bar0Abort as exc:
        print("\nSTOP: %s. Do nothing else; save this output." % exc)
        return 1
    finally:
        bar.close()


if __name__ == "__main__":
    sys.exit(main())
