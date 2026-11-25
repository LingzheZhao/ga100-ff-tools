#!/usr/bin/env python3
"""Read-only GA100 fuseless-fuse (FF) dump + decoder + bound defect masks.

Dumps raw FF rows (222-487), die-ID rows (8-15), defect masks (OPT_*_DEFECTIVE
+ OPT_PES_DISABLE/OPT_ROP_L2_DISABLE), and shadow OPT_* registers in ONE
single-card session so defects can never be mismatched across cards.

Hardened safety guarantees:
  - Single aligned 32-bit BAR0 reads/writes (never struct.pack_into).
  - --shadow-only opens resource0 O_RDONLY (cannot write GPU).
  - In raw mode, verifies FUSECTRL IDLE, BOOT0=GA100, GFW (0x118234) low byte
    == 0xFF, CRC_STATUS == 0x55, and DEBUGCTRL.RWL == 0 BEFORE reading shadow
    registers, defect masks, or issuing any CMD_READ (zero wasted reads on fault).
  - Aborts immediately on the first poison (0xBADxxxxx), dead BAR0, or row
    timeout — never loops through remaining rows or writes a partial dump.
  - Refuses to overwrite an existing --out file unless --force is given.

Run on the GPU host:
  sudo python3 planner/ff_dump.py --bdf 0000:01:00.0 --out card01-ff.json
  sudo python3 planner/ff_dump.py --bdf 0000:01:00.0 --all-rows --out card01-512.json
  sudo python3 planner/ff_dump.py --bdf 0000:01:00.0 --shadow-only
"""
import argparse
import datetime
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import (  # noqa: E402
    Bar0,
    Bar0Abort,
    CRC_STATUS,
    DEBUGCTRL,
    DEFECT_REGS,
    DSOV,
    EFP,
    EN_SW_OVERRIDE,
    FF_END,
    FF_START,
    FUSECTRL_PLM,
    FUSEOPT_PLM,
    FUSEWDATA_PLM,
    RWL_BIT,
    SBFE,
    WDATA_WR_SECURE,
    die_id_hash,
    gfw_ready,
    is_idle,
)

# Shadow / published option registers (pure MMIO reads).
SHADOW = {
    "OPT_GPC_DISABLE": 0x00820350,
    "OPT_FBP_DISABLE": 0x00820364,
    "OPT_FBPA_DISABLE": 0x00820368,
    "OPT_FBIO_DISABLE": 0x0082036C,
    "OPT_PCIE_DEVIDA": 0x008204D8,
    "OPT_PCIE_DEVIDB": 0x0082056C,
    "STATUS_OPT_GPC": 0x00820C1C,
    "STATUS_OPT_FBPA": 0x00820C18,
    "STATUS_OPT_FBP": 0x00820D38,
    "STATUS_OPT_FBIO": 0x00820C14,
}
for _i in range(8):
    SHADOW["OPT_TPC_DISABLE_GPC%d" % _i] = 0x00820760 + 4 * _i
    SHADOW["STATUS_OPT_TPC_GPC%d" % _i] = 0x00820C38 + 4 * _i

# Inferred FF option mapping: name -> (chain, lo_bit, hi_bit).
FF_OPTIONS = [
    ("OPT_FBIO_DISABLE", 1, 83, 106),
    ("OPT_FBPA_DISABLE", 1, 107, 130),
    ("OPT_GPC_DISABLE", 1, 131, 138),
    ("OPT_PES_DISABLE", 1, 251, 274),
    ("OPT_FBP_DISABLE", 1, 307, 318),
    ("OPT_ROP_L2_DISABLE", 1, 319, 342),
    ("OPT_NVLINK_DISABLE", 1, 368, 370),
    ("OPT_SYS_PIPE_DISABLE", 1, 372, 379),
    ("OPT_PCIE_DEVIDA", 2, 593, 608),
    ("OPT_PCIE_DEVIDB", 2, 609, 624),
]
for _i in range(8):
    FF_OPTIONS.append(("OPT_TPC_DISABLE_GPC%d" % _i, 1, 187 + 8 * _i, 194 + 8 * _i))


def decode_record(val):
    if val == 0:
        return None  # blank (unburned) row
    return {
        "chain": val & 0x1F,
        "iff": (val >> 5) & 1,
        "block": (val >> 6) & 0x3FF,
        "data": (val >> 16) & 0xFFFF,
    }


def build_chains(records):
    """chain -> {block: data}, last record per block wins."""
    chains = {}
    for rec in records:
        if rec is None or rec["iff"]:
            continue
        chains.setdefault(rec["chain"], {})[rec["block"]] = rec["data"]
    return chains


def chain_int(blockmap):
    v = 0
    for block, data in blockmap.items():
        v |= (data & 0xFFFF) << (16 * block)
    return v


def extract(chains, chain, lo, hi):
    if chain not in chains:
        return None
    v = chain_int(chains[chain])
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)


def _read_boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


def capture_with_bar(bar, bdf, start=FF_START, end=FF_END, shadow_only=False,
                     all_rows=False, read_die_id=True):
    # Gate 1: FUSECTRL IDLE, BOOT0=GA100, and GFW immediately (zero further reads on fault).
    health = bar.check_health_first(require_idle=True, require_gfw=True)
    crc = bar.rd_checked(CRC_STATUS, "CRC_STATUS")
    if not shadow_only and crc != 0x55:
        raise Bar0Abort("refused raw capture: CRC_STATUS=0x%02X (want 0x55; stopped immediately)" % crc)
    dbg = bar.rd_checked(DEBUGCTRL, "DEBUGCTRL")
    if not shadow_only and (dbg & RWL_BIT) != 0:
        raise Bar0Abort("refused raw capture: DEBUGCTRL.RWL!=0 (0x%08X; wrong array; STOP)" % dbg)

    dsov = bar.rd_checked(DSOV, "DSOV")
    efp = bar.rd_checked(EFP, "EFP")
    sbfe = bar.rd_checked(SBFE, "SBFE")
    en_sw = bar.rd_checked(EN_SW_OVERRIDE, "EN_SW_OVERRIDE")
    wdata_sec = bar.rd_checked(WDATA_WR_SECURE, "WDATA_WR_SECURE")
    wplm = bar.rd_checked(FUSEWDATA_PLM, "FUSEWDATA_PLM", allow_all_ones=True)
    cplm = bar.rd_checked(FUSECTRL_PLM, "FUSECTRL_PLM", allow_all_ones=True)
    oplm = bar.rd_checked(FUSEOPT_PLM, "FUSEOPT_PLM", allow_all_ones=True)

    idle = is_idle(health["fusectrl"])
    gfw_ok = gfw_ready(health["gfw"])
    report = {
        "schema_version": 2,
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "boot_id": _read_boot_id(),
        "bdf": bdf,
        "read_only": True,
        "shadow_only": shadow_only,
        "boot0": "0x%08X" % health["boot0"],
        "gfw": "0x%08X" % health["gfw"],
        "gfw_ready": gfw_ok,
        "fusectrl": "0x%08X" % health["fusectrl"],
        "crc_status": "0x%02X" % crc,
        "controller_idle": idle,
        "control": {
            "DSOV": "0x%08X" % dsov,
            "EFP": "0x%08X" % efp,
            "SBFE": "0x%08X" % sbfe,
            "EN_SW_OVERRIDE": "0x%08X" % en_sw,
            "DEBUGCTRL": "0x%08X" % dbg,
            "WDATA_WR_SECURE": "0x%08X" % wdata_sec,
            "FUSEWDATA_PLM": "0x%08X" % wplm,
            "FUSECTRL_PLM": "0x%08X" % cplm,
            "FUSEOPT_PLM": "0x%08X" % oplm,
        },
    }

    shadow = {n: "0x%08X" % bar.rd_checked(o, n) for n, o in SHADOW.items()}
    report["shadow"] = shadow
    defects = {n: "0x%08X" % bar.rd_checked(o, n) for n, o in DEFECT_REGS}
    report["defects"] = defects

    if shadow_only:
        return report

    if all_rows:
        raw_all = [bar.read_row(r) for r in range(512)]
        report["all_rows"] = {str(r): "0x%08X" % raw_all[r] for r in range(512)}
        die_vals = raw_all[8:16]
        report["die_id"] = ["0x%08X" % v for v in die_vals]
        report["die_id_hash"] = die_id_hash(die_vals)
        row_values = {r: raw_all[r] for r in range(start, end + 1)}
    else:
        if read_die_id:
            die_hex, die_hash = bar.read_die_id()
            report["die_id"] = die_hex
            report["die_id_hash"] = die_hash
        # Fail-fast: any timeout or poison raises Bar0Abort immediately.
        row_values = {r: bar.read_row(r) for r in range(start, end + 1)}

    rows = []
    records = []
    blank = []
    for row in range(start, end + 1):
        val = row_values[row]
        rec = decode_record(val)
        rows.append({"row": row, "raw": "0x%08X" % val, "record": rec})
        if rec is None:
            blank.append(row)
        else:
            records.append(rec)

    report["rows"] = rows
    report["blank_rows"] = blank
    report["read_errors"] = []
    chains = build_chains(records)
    report["chains"] = {
        str(c): {str(b): "0x%04X" % d for b, d in sorted(bm.items())}
        for c, bm in sorted(chains.items())
    }
    inferred = {}
    for name, c, lo, hi in FF_OPTIONS:
        v = extract(chains, c, lo, hi)
        inferred[name] = ("0x%X" % v) if v is not None else None
    report["inferred_ff_options"] = inferred
    return report


def main():
    ap = argparse.ArgumentParser(description="Read-only GA100 FF dump + bound defects + decoder")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--start", type=int, default=FF_START)
    ap.add_argument("--end", type=int, default=FF_END)
    ap.add_argument("--shadow-only", action="store_true",
                    help="pure MMIO reads of option/defect registers; O_RDONLY; zero fuse commands")
    ap.add_argument("--all-rows", action="store_true",
                    help="also archive all 512 physical fuse rows (0-511) in all_rows")
    ap.add_argument("--no-die-id", action="store_true",
                    help="skip reading die-ID rows 8-15 (not recommended; ffcard requires die_id)")
    ap.add_argument("--out", default=None, help="save JSON dump to this file (refuses existing unless --force)")
    ap.add_argument("--force", action="store_true", help="allow replacing an existing --out file")
    args = ap.parse_args()
    if sys.platform != "linux":
        print(json.dumps({"error": "Requires Linux (sysfs BAR0)"}))
        return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"}))
        return 2
    if not (0 <= args.start <= args.end <= 511):
        print(json.dumps({"error": "Invalid row range %d..%d" % (args.start, args.end)}))
        return 2
    if args.out and os.path.exists(args.out) and not args.force:
        print("ABORT: output file %s already exists (use a fresh filename or --force)" % args.out,
              file=sys.stderr)
        return 2

    try:
        bar = Bar0(args.bdf, read_only=args.shadow_only)
    except Bar0Abort as exc:
        print("STOP: %s" % exc, file=sys.stderr)
        return 1
    try:
        report = capture_with_bar(
            bar, args.bdf, start=args.start, end=args.end,
            shadow_only=args.shadow_only, all_rows=args.all_rows,
            read_die_id=(not args.no_die_id),
        )
    except Bar0Abort as exc:
        print("STOP: %s" % exc, file=sys.stderr)
        return 1
    finally:
        bar.close()

    # ---- console output ----
    print("=== GA100 FF dump (READ-ONLY) ===")
    print("BOOT0=%s  GFW=%s (ready=%s)  FUSECTRL=%s  CRC=%s  idle=%s  DSOV=%s" % (
        report["boot0"], report["gfw"], report["gfw_ready"],
        report["fusectrl"], report["crc_status"], report["controller_idle"],
        report["control"]["DSOV"],
    ))
    if "die_id_hash" in report:
        print("die_id_hash=%s  rows[8..15]=%s" % (report["die_id_hash"], ",".join(report["die_id"])))
    if args.shadow_only:
        print("\n-- shadow option registers (pure MMIO, no fuse commands) --")
        for n, v in report["shadow"].items():
            print("  %-26s %s" % (n, v))
    else:
        print("\n-- raw FF rows %d-%d --" % (args.start, args.end))
        print("  row  raw         chain block data   type")
        for r in report["rows"]:
            rec = r["record"]
            if rec is None:
                print("  %-4d %s  -     -     -      blank" % (r["row"], r["raw"]))
            else:
                print("  %-4d %s  %-5d %-5d 0x%04X %s" % (
                    r["row"], r["raw"], rec["chain"], rec["block"],
                    rec["data"], "IFF" if rec["iff"] else "FF",
                ))
        print("\n-- inferred FF option words vs shadow --")
        for name, c, lo, hi in FF_OPTIONS:
            inf = report["inferred_ff_options"].get(name)
            sh = report["shadow"].get(name, "-")
            print("  %-26s FF=%-10s shadow=%s" % (name, inf, sh))
        print("\n-- blank FF rows (available for append): %d --" % len(report["blank_rows"]))
        print("  %s" % report["blank_rows"])

    if args.out:
        tmp = args.out + ".tmp"
        with open(tmp, "w", encoding="ascii") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, args.out)
        print("\nsaved: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
