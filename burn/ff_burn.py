#!/usr/bin/env python3
"""Guarded single-record GA100 FF burn (main array). IRREVERSIBLE when confirmed.

Burns ONE planned fuseless-fuse record into a blank main-array row (222-487)
using CMD_WRITE, then reads it back to verify. DRY-RUN by default; nothing is
burned unless --confirm is passed AND you type BURN within the timeout.

Hardened safety guarantees:
  - Requires a verified plan JSON (no bare --row/--value bypass) and rejects
    negative or out-of-range --index.
  - Exclusive per-BDF flock lock prevents concurrent access to the same GPU.
  - Persistent burn journal (<plan>.journal.json by default) records IN_FLIGHT
    with fsync BEFORE CMD_WRITE and marks aborted=true on any timeout, poison,
    or readback mismatch — refusing all subsequent burns until resolved.
  - Fail-fast register prerequisites BEFORE any CMD_READ: FUSECTRL IDLE,
    BOOT0=GA100, GFW (0x118234 low byte == 0xFF), CRC=0x55, DSOV=0,
    EN_SW_OVERRIDE=1, SBFE=0, EFP=1, WDATA_WR_SECURE=0, FUSEWDATA_PLM,
    FUSECTRL_PLM, DEBUGCTRL.RWL=0.
  - Live card identity + full prefix verification: reads die-ID (rows 8-15),
    baseline rows (222..last_row) fingerprint, every prior_records + records[:index]
    burned prefix row, ensures no stray rows, and ensures target row is blank.
  - Re-verifies ALL register prerequisites AND FUSEADDR latch readback AFTER
    human types BURN (with confirmation expiry timeout). Note: NV_FUSE_FUSEWDATA
    (0x82000C) is hardware write-only (-W-4R) on GA100 and always reads back 0.
  - Single aligned 32-bit BAR0 writes (memoryview cast, never struct.pack_into);
    zero extra register reads and zero retries on poison/timeout/mismatch.

Run on the GPU host:
  sudo python3 burn/ff_burn.py --bdf 0000:01:00.0 --plan card_plan_sm_hbm.json --index 0
  sudo python3 burn/ff_burn.py --bdf 0000:01:00.0 --plan card_plan_sm_hbm.json --index 0 --confirm
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import sys
import time
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
    RWL_BIT,
    SBFE,
    WDATA_WR_SECURE,
    gfw_ready,
    is_idle,
)

# Bit-level protection for OPT_PCIE_DEVIDA/B including bit 0 of block (2, 39).
FORBIDDEN_BITS = {
    (2, 37): 0xFFFE,
    (2, 38): 0xFFFF,
    (2, 39): 0x0001,
}


def validate_target(row, value, rec=None):
    """Validate target row and 32-bit encoded FF word before touching hardware."""
    if not isinstance(row, int) or isinstance(row, bool) or not (FF_START <= row <= FF_END):
        raise ValueError("row %r outside FF region %d-%d" % (row, FF_START, FF_END))
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > 0xFFFFFFFF:
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
        r_old = int(rec["old_data"], 16)
        r_new = int(rec["new_data"], 16)
        expected = (r_new << 16) | (r_block << 6) | r_chain
        if expected != value:
            raise ValueError("plan record encoded 0x%08X != recomputed 0x%08X" % (value, expected))
        if (r_old ^ r_new) & FORBIDDEN_BITS.get((r_chain, r_block), 0):
            raise ValueError("plan record modifies forbidden device-ID bit in (%d, %d) — REFUSED"
                             % (r_chain, r_block))
    return chain, block


def validate_plan_and_index(plan, index):
    """Validate plan structure, baseline identity, and non-negative record index."""
    if not isinstance(plan, dict):
        raise ValueError("plan must be a JSON object")
    recs = plan.get("records")
    if not isinstance(recs, list) or not recs:
        raise ValueError("plan has no records")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0 or index >= len(recs):
        raise ValueError("--index %r out of range 0..%d (negative index refused)"
                         % (index, len(recs) - 1))
    base = plan.get("baseline")
    if not isinstance(base, dict):
        raise ValueError("plan is missing required 'baseline'")
    dh = base.get("die_id_hash")
    if not isinstance(dh, str) or len(dh) != 16:
        raise ValueError("plan baseline is missing required 16-char 'die_id_hash'")
    last_row = base.get("last_row")
    if not isinstance(last_row, int) or not (FF_START <= last_row <= FF_END):
        raise ValueError("plan baseline has invalid last_row %r" % (last_row,))
    fp = base.get("fingerprint")
    if not isinstance(fp, str) or len(fp) != 16:
        raise ValueError("plan baseline is missing required 16-char 'fingerprint'")

    # Validate every record in plan plus prior_records so prefix checks are trustworthy.
    expected_prefix = {}
    for pr in plan.get("prior_records", []):
        pr_row = pr["row"]
        pr_val = int(pr["encoded"], 16)
        validate_target(pr_row, pr_val)
        expected_prefix[pr_row] = pr_val
    for i, r in enumerate(recs):
        r_row = r["row"]
        r_val = int(r["encoded"], 16)
        validate_target(r_row, r_val, rec=r)
        if i < index:
            expected_prefix[r_row] = r_val

    rec = recs[index]
    row = rec["row"]
    value = int(rec["encoded"], 16)
    if row <= last_row:
        raise ValueError("target row %d overlaps baseline (last_row=%d)" % (row, last_row))
    for pr_row in expected_prefix:
        if pr_row >= row:
            raise ValueError("prior record row %d is not before target row %d" % (pr_row, row))
    return rec, row, value, base, expected_prefix


def _fingerprint_rows(row_vals, last_row):
    s = ",".join("0x%08X" % row_vals[i] for i in range(FF_START, last_row + 1))
    return hashlib.sha256(s.encode("ascii")).hexdigest()[:16]


def load_journal(journal_path):
    if journal_path is None or not os.path.exists(journal_path):
        return {"aborted": False, "entries": []}
    with open(journal_path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise ValueError("corrupted burn journal %s" % journal_path)
    return data


def check_journal_clear(journal_path):
    """Refuse to proceed if a prior burn aborted or stayed IN_FLIGHT."""
    j = load_journal(journal_path)
    if j.get("aborted"):
        return False, "journal %s is marked aborted=true (previous burn failed/uncertain; STOP)" % journal_path
    bad = [e for e in j.get("entries", []) if e.get("status") != "VERIFIED_OK"]
    if bad:
        return False, "journal %s has unresolved entry %s (STOP)" % (journal_path, bad[-1])
    return True, None


def _save_journal(journal_path, data):
    if journal_path is None:
        return
    parent = os.path.dirname(os.path.abspath(journal_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = journal_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, journal_path)


def check_register_guards(bar):
    """Fail-fast register-only guards; issues ZERO CMD_READs."""
    checks = []
    health = bar.check_health_first(require_idle=True, require_gfw=True)
    checks.append(("FUSECTRL IDLE", True, "0x%08X" % health["fusectrl"]))
    checks.append(("BOOT0 == GA100", True, "0x%08X" % health["boot0"]))
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
            return checks, False
    return checks, True


def check_prereqs(bar, row, base, expected_prefix):
    """Fail-fast register checks, then die-ID, baseline fingerprint, burned prefix, and blank target."""
    checks, reg_ok = check_register_guards(bar)
    if not reg_ok:
        return checks, False

    live_die_hex, live_hash = bar.read_die_id()
    want_hash = base["die_id_hash"]
    ok = (live_hash == want_hash)
    checks.append(("die-ID (rows 8-15) hash match", ok, "%s (want %s)" % (live_hash, want_hash)))
    if not ok:
        return checks, False
    if "die_id" in base:
        ok_rows = (live_die_hex == base["die_id"])
        checks.append(("die-ID raw rows exact match", ok_rows, "match" if ok_rows else "MISMATCH"))
        if not ok_rows:
            return checks, False

    # Verify baseline rows 222..last_row fingerprint matches the planned card!
    last_row = base["last_row"]
    base_vals = {r: bar.read_row(r) for r in range(FF_START, last_row + 1)}
    live_fp = _fingerprint_rows(base_vals, last_row)
    ok_fp = (live_fp == base["fingerprint"])
    checks.append(("baseline rows %d-%d fingerprint" % (FF_START, last_row), ok_fp,
                   "%s (want %s)" % (live_fp, base["fingerprint"])))
    if not ok_fp:
        return checks, False

    # Verify every row between last_row+1 and target row - 1 matches expected burned prefix (or blank gap).
    for r in range(last_row + 1, row):
        got = bar.read_row(r)
        if r in expected_prefix:
            want = expected_prefix[r]
            if got != want:
                checks.append(("prior burned row %d" % r, False,
                               "0x%08X (want 0x%08X — do NOT skip records!)" % (got, want)))
                return checks, False
        else:
            if got != 0:
                checks.append(("intervening row %d blank" % r, False,
                               "0x%08X (unexpected stray write)" % got))
                return checks, False
    if expected_prefix:
        checks.append(("burned prefix (%d prior rows)" % len(expected_prefix), True, "all match"))

    cur = bar.read_row(row)
    ok_blank = (cur == 0)
    checks.append(("target row %d blank" % row, ok_blank, "0x%08X" % cur))
    return checks, ok_blank


def execute_plan(bar, plan, index, confirm=False, input_fn=input, journal_path=None,
                 confirm_timeout_s=60.0, plan_name="<plan>"):
    rec, row, value, base, expected_prefix = validate_plan_and_index(plan, index)

    print("=== FF burn %s ===" % ("CONFIRMED" if confirm else "DRY-RUN"))
    print("plan:   %s  card=%s  mode=%s  index=%d/%d" % (
        plan_name, plan.get("card", "?"), plan.get("mode", "?"),
        index, len(plan["records"]),
    ))
    print("die_id: %s  baseline rows %d-%d fp=%s" % (
        base["die_id_hash"], FF_START, base["last_row"], base["fingerprint"],
    ))
    print("target: row %d = 0x%08X  chain %d block %d  %s -> %s%s%s" % (
        row, value, rec["chain"], rec["block"], rec["old_data"], rec["new_data"],
        ("  SETS %s" % rec["sets_bits"]) if "sets_bits" in rec else "",
        ("  (%s)" % rec["note"]) if "note" in rec else "",
    ))

    # Persistent abort lock check before touching hardware!
    j_ok, j_err = check_journal_clear(journal_path)
    if not j_ok:
        print("ABORT: %s" % j_err)
        return 1

    checks, all_ok = check_prereqs(bar, row, base, expected_prefix)
    for name, ok, val in checks:
        print("  [%s] %-34s %s" % ("OK" if ok else "FAIL", name, val))
    if not all_ok:
        print("\nABORT: prerequisites not met. Stopped immediately; no write performed.")
        return 1
    if not confirm:
        print("\nDRY-RUN: all checks passed (CMD_READ used to verify die-ID, baseline, prefix, blank row).")
        print("Would burn row %d = 0x%08X (chain %d block %d: %s -> %s). Re-run with --confirm (IRREVERSIBLE)."
              % (row, value, rec["chain"], rec["block"], rec["old_data"], rec["new_data"]))
        return 0

    print("\n*** IRREVERSIBLE FUSE BURN ***")
    t_prompt = time.monotonic()
    try:
        resp = input_fn("Type BURN within %.0fs to write row %d = 0x%08X (%s -> %s): "
                        % (confirm_timeout_s, row, value, rec["old_data"], rec["new_data"]))
    except EOFError:
        resp = ""
    if confirm_timeout_s is not None and (time.monotonic() - t_prompt) > confirm_timeout_s:
        print("ABORT: confirmation expired (> %.0fs). Re-run dry-run; no write performed." % confirm_timeout_s)
        return 1
    if resp.strip() != "BURN":
        print("ABORT: not confirmed. No write performed.")
        return 1

    # Re-verify ALL register guards immediately after human confirmation!
    rechecks, re_ok = check_register_guards(bar)
    if not re_ok:
        failed = next((c for c in rechecks if not c[1]), ("unknown", False, "?"))
        print("ABORT: register guard failed after confirmation (%s = %s). No write performed."
              % (failed[0], failed[2]))
        return 1

    # Latch address (read-write, verify readback) and write data (NV_FUSE_FUSEWDATA
    # 0x82000C is hardware write-only -W-4R on GA100 and always reads back 0).
    bar.wr(FUSECTRL, CMD_IDLE)
    bar.wr(FUSEADDR, row)
    addr_rb = bar.rd_checked(FUSEADDR, "FUSEADDR")
    if addr_rb != row:
        raise Bar0Abort("FUSEADDR did not latch row %d (got 0x%08X; STOP before CMD_WRITE)" % (row, addr_rb))
    bar.wr(FUSEWDATA, value)

    # Persist IN_FLIGHT (aborted=True until verified) + fsync BEFORE irreversible CMD_WRITE.
    journal = load_journal(journal_path)
    entry = {
        "utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plan": plan_name,
        "index": index,
        "row": row,
        "encoded": "0x%08X" % value,
        "die_id_hash": base["die_id_hash"],
        "status": "IN_FLIGHT",
    }
    journal["aborted"] = True
    journal["entries"].append(entry)
    _save_journal(journal_path, journal)

    try:
        bar.wr(FUSECTRL, CMD_WRITE)
        # Fail-fast: timeout or poison raises Bar0Abort with ZERO extra reads.
        bar.poll_idle(5000)
        readback = bar.read_row(row)
    except Bar0Abort as exc:
        entry["status"] = "ABORTED_IO"
        entry["error"] = str(exc)
        journal["aborted"] = True
        _save_journal(journal_path, journal)
        raise

    if readback == value:
        entry["status"] = "VERIFIED_OK"
        entry["readback"] = "0x%08X" % readback
        journal["aborted"] = False
        _save_journal(journal_path, journal)
        print("VERIFY OK: row %d = 0x%08X" % (row, readback))
        if plan.get("mode") == "noop":
            print("Burn landed. For a no-op test, effective config is unchanged.")
        return 0

    entry["status"] = "VERIFY_FAIL"
    entry["readback"] = "0x%08X" % readback
    journal["aborted"] = True
    _save_journal(journal_path, journal)
    print("VERIFY FAIL: expected 0x%08X, got 0x%08X. STOP. Journal locked (aborted=true). Do NOT retry."
          % (value, readback))
    return 1


def main():
    ap = argparse.ArgumentParser(description="Guarded single FF burn from verified plan (IRREVERSIBLE)")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--plan", required=True, help="verified per-card plan JSON from ffcard.py derive")
    ap.add_argument("--index", type=int, default=0, help="non-negative record index in plan (default 0)")
    ap.add_argument("--journal", default=None,
                    help="persistent burn journal path (default: <plan>.journal.json)")
    ap.add_argument("--confirm-timeout", type=float, default=60.0,
                    help="seconds before BURN confirmation expires (default 60)")
    ap.add_argument("--lock-file", default=None,
                    help="exclusive flock path (default: /run/lock/ga100-ff-burn-<bdf>.lock)")
    ap.add_argument("--confirm", action="store_true", help="actually burn (else dry-run)")
    args = ap.parse_args()
    if sys.platform != "linux":
        print(json.dumps({"error": "Requires Linux"}))
        return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"}))
        return 2

    with open(args.plan, encoding="utf-8") as f:
        plan = json.load(f)
    try:
        validate_plan_and_index(plan, args.index)
    except (ValueError, KeyError) as exc:
        print("ABORT: %s" % exc)
        return 2

    journal_path = args.journal or (args.plan + ".journal.json")
    lock_path = args.lock_file or ("/run/lock/ga100-ff-burn-%s.lock" % args.bdf.replace(":", "_"))
    lock_fd = None
    try:
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("ABORT: another ff_burn.py holds lock %s for %s" % (lock_path, args.bdf))
        if lock_fd is not None:
            os.close(lock_fd)
        return 1
    except OSError as exc:
        print("ABORT: cannot acquire lock %s: %s" % (lock_path, exc))
        if lock_fd is not None:
            os.close(lock_fd)
        return 1

    try:
        try:
            bar = Bar0(args.bdf, read_only=False)
        except Bar0Abort as exc:
            print("STOP: %s" % exc)
            return 1
        try:
            return execute_plan(
                bar, plan, args.index, confirm=args.confirm,
                journal_path=journal_path,
                confirm_timeout_s=args.confirm_timeout,
                plan_name=os.path.basename(args.plan),
            )
        except Bar0Abort as exc:
            print("STOP: %s. Do NOT retry; save this output." % exc)
            return 1
        finally:
            bar.close()
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
