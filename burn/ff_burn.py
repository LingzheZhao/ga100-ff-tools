#!/usr/bin/env python3
"""Guarded single-record GA100 FF burn (main array). IRREVERSIBLE when confirmed.

Burns ONE fuseless-fuse record into a blank main-array row (222-487) using
CMD_WRITE, then reads it back to verify. DRY-RUN by default; nothing is burned
unless --confirm is passed AND you type BURN at the prompt.

Hardened safety guarantees:
  - Single aligned 32-bit BAR0 writes (memoryview cast, never struct.pack_into).
  - Strictly validates target row (222-487), 32-bit non-zero value, IFF bit=0,
    and forbids chain 2 blocks 37/38 (PCIe device ID).
  - Fail-fast prerequisites BEFORE issuing any CMD_READ: checks FUSECTRL IDLE,
    BOOT0, GFW_BOOT (0x118234 low byte == 0xFF), CRC=0x55, DSOV=0,
    EN_SW_OVERRIDE=1, SBFE=0, EFP=1, WDATA_WR_SECURE=0, FUSEWDATA_PLM,
    FUSECTRL_PLM, DEBUGCTRL.RWL=0. Only after ALL register guards pass does it
    issue CMD_READ on die-ID rows (when bound in plan) and the target row.
  - Zero extra register reads and zero retries on poison/timeout/mismatch.

Run on the GPU host:
  sudo python3 burn/ff_burn.py --bdf 0000:01:00.0 --plan card_plan_sm_hbm.json --index 0
  sudo python3 burn/ff_burn.py --bdf 0000:01:00.0 --plan card_plan_sm_hbm.json --index 0 --confirm
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
    CMD_IDLE,
    CMD_WRITE,
    CRC_STATUS,
    DEBUGCTRL,
    DSOV,
    EFP,
    EN_SW_OVERRIDE,
    FF_END,
    FF_START,
    FORBIDDEN_BLOCKS,
    FUSEADDR,
    FUSECTRL,
    FUSECTRL_PLM,
    FUSEWDATA,
    FUSEWDATA_PLM,
    GFW_BOOT,
    RWL_BIT,
    SBFE,
    WDATA_WR_SECURE,
    gfw_ready,
    is_idle,
)


def validate_target(row, value, rec=None):
    """Validate target row and 32-bit encoded FF word before touching hardware."""
    if not isinstance(row, int) or not (FF_START <= row <= FF_END):
        raise ValueError("row %r outside FF region %d-%d" % (row, FF_START, FF_END))
    if not isinstance(value, int) or value <= 0 or value > 0xFFFFFFFF:
        raise ValueError("value %r must be a non-zero 32-bit integer" % (value,))
    if value & 0x20:
        raise ValueError("value 0x%08X has IFF bit (bit 5) set — REFUSED" % value)
    chain = value & 0x1F
    block = (value >> 6) & 0x3FF
    if (chain, block) in FORBIDDEN_BLOCKS:
        raise ValueError("value 0x%08X targets forbidden device-ID block (%d, %d) — REFUSED"
                         % (value, chain, block))
    if rec is not None:
        r_chain = rec["chain"]
        r_block = rec["block"]
        r_new = int(rec["new_data"], 16)
        expected = (r_new << 16) | (r_block << 6) | r_chain
        if expected != value:
            raise ValueError("plan record encoded 0x%08X != recomputed 0x%08X" % (value, expected))
    return chain, block


def check_prereqs(bar, row, expected_die_id_hash=None):
    """Fail-fast prerequisite check; NEVER issues CMD_READ until every register guard passes."""
    checks = []
    health = bar.check_health_first(require_idle=True, require_gfw=True)
    checks.append(("FUSECTRL IDLE", True, "0x%08X" % health["fusectrl"]))
    checks.append(("BOOT0 valid", True, "0x%08X" % health["boot0"]))
    checks.append(("GFW_BOOT low byte 0xFF", gfw_ready(health["gfw"]), "0x%08X" % health["gfw"]))

    reg_guards = [
        ("CRC_STATUS=0x55", CRC_STATUS, lambda v: v == 0x55, "0x%02X", False),
        ("DSOV=0", DSOV, lambda v: v == 0, "0x%X", False),
        ("EN_SW_OVERRIDE=1", EN_SW_OVERRIDE, lambda v: (v & 1) == 1, "0x%X", False),
        ("SBFE=0", SBFE, lambda v: v == 0, "0x%X", False),
        ("EFP=1", EFP, lambda v: v == 1, "0x%X", False),
        ("WDATA_WR_SECURE=0", WDATA_WR_SECURE, lambda v: v == 0, "0x%08X", False),
        ("FUSEWDATA_PLM open", FUSEWDATA_PLM, lambda v: v == 0xFFFFFFFF, "0x%08X", True),
        ("FUSECTRL_PLM open", FUSECTRL_PLM, lambda v: v == 0xFFFFFFFF, "0x%08X", True),
        ("DEBUGCTRL.RWL=0 (main array)", DEBUGCTRL, lambda v: (v & RWL_BIT) == 0, "0x%08X", False),
    ]
    for name, off, pred, fmt, allow_ones in reg_guards:
        val = bar.rd_checked(off, name, allow_all_ones=allow_ones)
        ok = pred(val)
        checks.append((name, ok, fmt % val))
        if not ok:
            # Fail-fast: do NOT read further registers or issue CMD_READ!
            return checks, False

    if expected_die_id_hash is not None:
        _, live_hash = bar.read_die_id()
        ok = (live_hash == expected_die_id_hash)
        checks.append(("die-ID (rows 8-15) match", ok, "%s (want %s)" % (live_hash, expected_die_id_hash)))
        if not ok:
            return checks, False

    cur = bar.read_row(row)
    ok = (cur == 0)
    checks.append(("target row blank", ok, "0x%08X" % cur))
    return checks, ok


def execute(bar, row, value, confirm=False, expected_die_id_hash=None, input_fn=input):
    print("=== FF burn %s ===" % ("CONFIRMED" if confirm else "DRY-RUN"))
    print("target: row %d = 0x%08X" % (row, value))
    checks, all_ok = check_prereqs(bar, row, expected_die_id_hash=expected_die_id_hash)
    for name, ok, val in checks:
        print("  [%s] %-32s %s" % ("OK" if ok else "FAIL", name, val))
    if not all_ok:
        print("\nABORT: prerequisites not met. Stopped immediately; no write performed.")
        return 1
    if not confirm:
        print("\nDRY-RUN: all checks passed (note: CMD_READ was used to verify blank row).")
        print("Would burn row %d = 0x%08X. Re-run with --confirm to execute (IRREVERSIBLE)."
              % (row, value))
        return 0

    print("\n*** IRREVERSIBLE FUSE BURN ***")
    try:
        resp = input_fn("Type BURN to write row %d = 0x%08X: " % (row, value))
    except EOFError:
        resp = ""
    if resp.strip() != "BURN":
        print("ABORT: not confirmed. No write performed.")
        return 1

    # Re-confirm controller is still IDLE immediately before CMD_WRITE.
    fc = bar.rd_checked(FUSECTRL, "FUSECTRL")
    if not is_idle(fc):
        print("ABORT: FUSECTRL no longer IDLE (0x%08X). No write performed." % fc)
        return 1

    bar.wr(FUSECTRL, CMD_IDLE)
    bar.wr(FUSEADDR, row)
    bar.wr(FUSEWDATA, value)
    bar.wr(FUSECTRL, CMD_WRITE)
    # Fail-fast: timeout or poison raises Bar0Abort with ZERO extra reads.
    bar.poll_idle(5000)

    readback = bar.read_row(row)
    if readback == value:
        print("VERIFY OK: row %d = 0x%08X" % (row, readback))
        print("Burn landed. For a no-op test, effective config is unchanged.")
        return 0
    print("VERIFY FAIL: expected 0x%08X, got 0x%08X. STOP. Do NOT retry." % (value, readback))
    return 1


def main():
    ap = argparse.ArgumentParser(description="Guarded single FF burn (IRREVERSIBLE)")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--row", type=int)
    ap.add_argument("--value", type=lambda x: int(x, 0))
    ap.add_argument("--plan", help="load record from a plan JSON")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--confirm", action="store_true", help="actually burn (else dry-run)")
    args = ap.parse_args()
    if sys.platform != "linux":
        print(json.dumps({"error": "Requires Linux"}))
        return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"}))
        return 2

    rec = None
    expected_die_id_hash = None
    if args.plan:
        with open(args.plan, encoding="utf-8") as f:
            plan = json.load(f)
        rec = plan["records"][args.index]
        row = rec["row"]
        value = int(rec["encoded"], 16)
        expected_die_id_hash = (plan.get("baseline") or {}).get("die_id_hash")
    else:
        if args.row is None or args.value is None:
            print("need --row and --value, or --plan")
            return 2
        row, value = args.row, args.value

    try:
        validate_target(row, value, rec=rec)
    except (ValueError, KeyError) as exc:
        print("ABORT: %s" % exc)
        return 2

    try:
        bar = Bar0(args.bdf, read_only=False)
    except Bar0Abort as exc:
        print("STOP: %s" % exc)
        return 1
    try:
        return execute(bar, row, value, confirm=args.confirm,
                       expected_die_id_hash=expected_die_id_hash)
    except Bar0Abort as exc:
        print("STOP: %s. Do NOT retry; save this output." % exc)
        return 1
    finally:
        bar.close()


if __name__ == "__main__":
    sys.exit(main())
