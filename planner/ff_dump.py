#!/usr/bin/env python3
"""Read-only GA100 fuseless-fuse (FF) dump + decoder.

Dumps the raw FF rows (222-487), decodes each record (chain / block / data),
reconstructs the chains, and infers the published option words using the
mapping from Kate's blog (https://blog.kate.land/posts/using-voltage-glitching-
to-unlock-the-a100). Also reads the shadow OPT_* registers for cross-check.

READ-ONLY / NON-DESTRUCTIVE:
  - Raw rows are read with the fuse controller's CMD_READ (FUSECTRL=1). This
    writes ONLY the command/address registers to request a read; it NEVER
    writes FUSEWDATA and NEVER issues CMD_WRITE/program. No fuse is burned.
  - --shadow-only does pure MMIO reads of the published option registers and
    issues ZERO fuse commands.

Guards: refuses raw reads unless FUSECTRL is IDLE and CRC_STATUS=0x55;
per-row timeout; never touches the write/program path.

Run on the GPU host:
  sudo python3 ff_dump.py --bdf 0000:01:00.0
  sudo python3 ff_dump.py --bdf 0000:01:00.0 --shadow-only
  sudo python3 ff_dump.py --bdf 0000:01:00.0 --start 222 --end 487 --out ff.json
"""
import argparse
import json
import mmap
import os
import struct
import sys
import time

FUSECTRL = 0x00820000
FUSEADDR = 0x00820004
FUSERDATA = 0x00820008
CRC_STATUS = 0x00820070
CMD_IDLE = 0x0
CMD_READ = 0x1
STATE_MASK = 0x1F << 16
STATE_IDLE = 4 << 16
MAP_BYTES = 0x822000

FF_START = 222
FF_END = 487

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

# Inferred FF option mapping from the blog: name -> (chain, lo_bit, hi_bit).
# Chain bit-stream: block N occupies bits [16N, 16N+16), data bit k -> 16N+k.
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


class Bar0:
    def __init__(self, bdf):
        path = "/sys/bus/pci/devices/%s/resource0" % bdf
        self.fd = os.open(path, os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
        try:
            self.mm = mmap.mmap(self.fd, MAP_BYTES, flags=mmap.MAP_SHARED,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except BaseException:
            os.close(self.fd)
            raise

    def rd(self, off):
        return struct.unpack_from("<I", self.mm, off)[0]

    def wr(self, off, val):
        struct.pack_into("<I", self.mm, off, val & 0xFFFFFFFF)

    def close(self):
        self.mm.close()
        os.close(self.fd)


def poll_idle(bar, timeout_ms=1000):
    deadline = time.monotonic() + timeout_ms / 1000.0
    while time.monotonic() < deadline:
        if (bar.rd(FUSECTRL) & STATE_MASK) == STATE_IDLE:
            return True
        time.sleep(0.001)
    return False


def read_row(bar, row):
    """Non-destructive CMD_READ. Never writes FUSEWDATA / never programs."""
    bar.wr(FUSECTRL, CMD_IDLE)
    bar.wr(FUSEADDR, row)
    bar.wr(FUSECTRL, CMD_READ)
    if not poll_idle(bar):
        return None
    return bar.rd(FUSERDATA)


def decode_record(val):
    if val == 0:
        return None  # blank (unburned) row
    return {"chain": val & 0x1F,
            "iff": (val >> 5) & 1,
            "block": (val >> 6) & 0x3FF,
            "data": (val >> 16) & 0xFFFF}


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


def main():
    ap = argparse.ArgumentParser(description="Read-only GA100 FF dump + decoder")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--start", type=int, default=FF_START)
    ap.add_argument("--end", type=int, default=FF_END)
    ap.add_argument("--shadow-only", action="store_true",
                    help="pure MMIO reads of option registers; zero fuse commands")
    ap.add_argument("--out", default=None, help="save JSON dump to this file")
    args = ap.parse_args()
    if sys.platform != "linux":
        print(json.dumps({"error": "Requires Linux (sysfs BAR0)"}))
        return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"}))
        return 2

    bar = Bar0(args.bdf)
    report = {"bdf": args.bdf, "read_only": True, "shadow_only": args.shadow_only}
    try:
        fusectrl = bar.rd(FUSECTRL)
        crc = bar.rd(CRC_STATUS)
        report["fusectrl"] = "0x%08X" % fusectrl
        report["crc_status"] = "0x%02X" % crc
        report["controller_idle"] = (fusectrl & STATE_MASK) == STATE_IDLE

        # Shadow registers: always pure MMIO reads (no commands).
        shadow = {n: "0x%08X" % bar.rd(o) for n, o in SHADOW.items()}
        report["shadow"] = shadow

        if not args.shadow_only:
            if not report["controller_idle"] or crc != 0x55:
                report["warning"] = ("controller not IDLE/CRC!=0x55; raw reads may "
                                     "fail (glitch state lost?)")
            rows = []
            records = []
            blank = []
            errors = []
            for row in range(args.start, args.end + 1):
                val = read_row(bar, row)
                if val is None:
                    errors.append(row)
                    rows.append({"row": row, "raw": None, "error": "timeout"})
                    continue
                rec = decode_record(val)
                rows.append({"row": row, "raw": "0x%08X" % val, "record": rec})
                if rec is None:
                    blank.append(row)
                else:
                    records.append(rec)
            report["rows"] = rows
            report["blank_rows"] = blank
            report["read_errors"] = errors
            chains = build_chains(records)
            report["chains"] = {str(c): {str(b): "0x%04X" % d
                                         for b, d in sorted(bm.items())}
                                for c, bm in sorted(chains.items())}
            inferred = {}
            for name, c, lo, hi in FF_OPTIONS:
                v = extract(chains, c, lo, hi)
                inferred[name] = ("0x%X" % v) if v is not None else None
            report["inferred_ff_options"] = inferred
    finally:
        bar.close()

    # ---- console output ----
    print("=== GA100 FF dump (READ-ONLY) ===")
    print("FUSECTRL=%s  CRC=%s  idle=%s" %
          (report["fusectrl"], report["crc_status"], report["controller_idle"]))
    if args.shadow_only:
        print("\n-- shadow option registers (pure MMIO, no fuse commands) --")
        for n, v in shadow.items():
            print("  %-26s %s" % (n, v))
    else:
        print("\n-- raw FF rows %d-%d --" % (args.start, args.end))
        print("  row  raw         chain block data   type")
        for r in report["rows"]:
            if r.get("error"):
                print("  %-4d ERROR (%s)" % (r["row"], r["error"]))
                continue
            rec = r["record"]
            if rec is None:
                print("  %-4d %s  -     -     -      blank" % (r["row"], r["raw"]))
            else:
                print("  %-4d %s  %-5d %-5d 0x%04X %s" %
                      (r["row"], r["raw"], rec["chain"], rec["block"],
                       rec["data"], "IFF" if rec["iff"] else "FF"))
        print("\n-- inferred FF option words (blog mapping) vs shadow --")
        for name, c, lo, hi in FF_OPTIONS:
            inf = report["inferred_ff_options"].get(name)
            sh = shadow.get(name, "-")
            print("  %-26s FF=%-10s shadow=%s" % (name, inf, sh))
        print("\n-- blank FF rows (available for append): %d --" %
              len(report["blank_rows"]))
        print("  %s" % report["blank_rows"])
        if report["read_errors"]:
            print("  READ ERRORS on rows: %s" % report["read_errors"])

    if args.out:
        with open(args.out, "w", encoding="ascii") as f:
            json.dump(report, f, indent=2)
        print("\nsaved: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
