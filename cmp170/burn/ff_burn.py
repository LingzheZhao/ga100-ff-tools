#!/usr/bin/env python3
"""Guarded single-record GA100 FF burn (main array). IRREVERSIBLE when confirmed.

Burns ONE fuseless-fuse record into a blank main-array row (222-487) using
CMD_WRITE, then reads it back to verify. DRY-RUN by default; nothing is written
unless --confirm is passed AND you type BURN at the prompt.

Protocol (main array, DEBUGCTRL.RWL=0; RWL=1 is the separate RIR macro):
  FUSECTRL=0 -> FUSEADDR=row -> FUSEWDATA=value -> FUSECTRL=CMD_WRITE(2)
  -> poll IDLE -> CMD_READ row -> verify.

Guards (all must pass before any write):
  FUSECTRL IDLE, CRC=0x55, DSOV=0, SBFE=0, EFP=1,
  FUSEWDATA_PLM=0xFFFFFFFF, FUSECTRL_PLM=0xFFFFFFFF, DEBUGCTRL.RWL=0,
  target row reads blank (0x00000000). Aborts on any failure; NO retry.

Run on the GPU host:
  sudo python3 ff_burn.py --bdf 0000:01:00.0 --row 293 --value 0x019801C1
      (dry-run; add --confirm to actually burn)
  sudo python3 ff_burn.py --bdf 0000:01:00.0 --plan ff_plan.json --index 0 --confirm
      (ff_plan.json = your derived plan from ff_derive.py; not shipped)
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
FUSEWDATA = 0x0082000C
DEBUGCTRL = 0x00820060
RWL_BIT = 1 << 1
CRC_STATUS = 0x00820070
EFP = 0x00820078
DSOV = 0x00820084
FUSEWDATA_PLM = 0x008200F4
FUSECTRL_PLM = 0x008200F8
SBFE = 0x00821108
CMD_READ = 0x1
CMD_WRITE = 0x2
STATE_MASK = 0x1F << 16
STATE_IDLE = 4 << 16
MAP_BYTES = 0x822000
FF_START, FF_END = 222, 487


class Bar0:
    def __init__(self, bdf):
        self.fd = os.open("/sys/bus/pci/devices/%s/resource0" % bdf,
                          os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
        try:
            self.mm = mmap.mmap(self.fd, MAP_BYTES, flags=mmap.MAP_SHARED,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except BaseException:
            os.close(self.fd)
            raise

    def rd(self, o):
        return struct.unpack_from("<I", self.mm, o)[0]

    def wr(self, o, v):
        struct.pack_into("<I", self.mm, o, v & 0xFFFFFFFF)

    def close(self):
        self.mm.close()
        os.close(self.fd)


def poll_idle(bar, ms):
    end = time.monotonic() + ms / 1000.0
    while time.monotonic() < end:
        if (bar.rd(FUSECTRL) & STATE_MASK) == STATE_IDLE:
            return True
        time.sleep(0.001)
    return False


def read_row(bar, row):
    bar.wr(FUSECTRL, 0)
    bar.wr(FUSEADDR, row)
    bar.wr(FUSECTRL, CMD_READ)
    if not poll_idle(bar, 1000):
        return None
    return bar.rd(FUSERDATA)


def check_prereqs(bar, row):
    checks = []
    fc = bar.rd(FUSECTRL)
    checks.append(("FUSECTRL IDLE", (fc & STATE_MASK) == STATE_IDLE, "0x%08X" % fc))
    crc = bar.rd(CRC_STATUS)
    checks.append(("CRC_STATUS=0x55", crc == 0x55, "0x%02X" % crc))
    dsov = bar.rd(DSOV)
    checks.append(("DSOV=0", dsov == 0, "0x%X" % dsov))
    sbfe = bar.rd(SBFE)
    checks.append(("SBFE=0", sbfe == 0, "0x%X" % sbfe))
    efp = bar.rd(EFP)
    checks.append(("EFP=1", efp == 1, "0x%X" % efp))
    wplm = bar.rd(FUSEWDATA_PLM)
    checks.append(("FUSEWDATA_PLM open", wplm == 0xFFFFFFFF, "0x%08X" % wplm))
    cplm = bar.rd(FUSECTRL_PLM)
    checks.append(("FUSECTRL_PLM open", cplm == 0xFFFFFFFF, "0x%08X" % cplm))
    dbg = bar.rd(DEBUGCTRL)
    checks.append(("DEBUGCTRL.RWL=0 (main array)", (dbg & RWL_BIT) == 0, "0x%08X" % dbg))
    blank = read_row(bar, row)
    checks.append(("target row blank", blank == 0, "0x%08X" % (blank if blank is not None else 0xFFFFFFFF)))
    return checks


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
        print(json.dumps({"error": "Requires Linux"})); return 2
    if os.geteuid() != 0:
        print(json.dumps({"error": "Run with sudo"})); return 2

    if args.plan:
        with open(args.plan, encoding="ascii") as f:
            plan = json.load(f)
        rec = plan["records"][args.index]
        row = rec["row"]
        value = int(rec["encoded"], 16)
    else:
        if args.row is None or args.value is None:
            print("need --row and --value, or --plan"); return 2
        row, value = args.row, args.value

    if not (FF_START <= row <= FF_END):
        print("ABORT: row %d outside FF region %d-%d" % (row, FF_START, FF_END)); return 2

    bar = Bar0(args.bdf)
    try:
        print("=== FF burn %s ===" % ("CONFIRMED" if args.confirm else "DRY-RUN"))
        print("target: row %d = 0x%08X" % (row, value))
        checks = check_prereqs(bar, row)
        all_ok = True
        for name, ok, val in checks:
            print("  [%s] %-32s %s" % ("OK" if ok else "FAIL", name, val))
            all_ok = all_ok and ok
        if not all_ok:
            print("\nABORT: prerequisites not met. No write performed.")
            return 1
        if not args.confirm:
            print("\nDRY-RUN: all checks passed. Would burn row %d = 0x%08X." % (row, value))
            print("Re-run with --confirm to execute (IRREVERSIBLE).")
            return 0

        print("\n*** IRREVERSIBLE FUSE BURN ***")
        try:
            resp = input("Type BURN to write row %d = 0x%08X: " % (row, value))
        except EOFError:
            resp = ""
        if resp.strip() != "BURN":
            print("ABORT: not confirmed. No write performed.")
            return 1

        # ensure RWL clear (main array), preserve other DEBUGCTRL bits
        dbg = bar.rd(DEBUGCTRL)
        if dbg & RWL_BIT:
            bar.wr(DEBUGCTRL, dbg & ~RWL_BIT)
        bar.wr(FUSECTRL, 0)
        bar.wr(FUSEADDR, row)
        bar.wr(FUSEWDATA, value)
        bar.wr(FUSECTRL, CMD_WRITE)
        if not poll_idle(bar, 5000):
            print("ERROR: write did not complete (FUSECTRL=0x%08X). STOP. No retry."
                  % bar.rd(FUSECTRL))
            return 1
        readback = read_row(bar, row)
        if readback == value:
            print("VERIFY OK: row %d = 0x%08X" % (row, readback))
            print("Burn landed. For a no-op test, effective config is unchanged.")
            return 0
        print("VERIFY FAIL: expected 0x%08X, got 0x%08X. STOP. Do NOT retry."
              % (value, readback if readback is not None else 0xFFFFFFFF))
        return 1
    finally:
        bar.close()


if __name__ == "__main__":
    sys.exit(main())
