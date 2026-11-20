#!/usr/bin/env python3
"""Arm fuse programming after a Goldilocks glitch: FUSECTRL SENSE_CTRL. NO BURN.

Kate's sequence (blog.kate.land, "Goldilock's glitch"): the shallow glitch reads
row 0/1 control fuses as zero, so DSOV=0 but also ENABLE_FUSE_PROGRAM (EFP)=0,
which blocks burns. Issuing the fuse controller SENSE_CTRL command restores the
control-fuse options to their fused values EXCEPT DSOV, which stays 0 -> EFP=1.
SBFE may come back as 1; clear it via the option shadow (--clear-sbfe).

SENSE_CTRL = FUSECTRL cmd 3 (user-supplied; consistent with the Tegra-lineage
fuse controller: IDLE=0 READ=1 WRITE=2 SENSE_CTRL=3, STATE IDLE=4). Not
confirmed by any source in this repo.

Safety latch: FUSEWDATA is set to 0 and read back BEFORE the command. OTP is
0->1 only, so even if cmd 3 were a program cycle it could not set any bit.

  sudo python3 arm_sense_ctrl.py --bdf 0000:01:00.0              # dry-run
  sudo python3 arm_sense_ctrl.py --bdf 0000:01:00.0 --confirm    # type SENSE
  sudo python3 arm_sense_ctrl.py --bdf 0000:01:00.0 --clear-sbfe # after sense
Then: sw_override.py, open_wdata_plm.py, ff_burn.py dry-run (EFP=1 must be OK).
"""
import argparse
import mmap
import os
import struct
import sys
import time

BOOT0 = 0x00000000
FUSECTRL = 0x00820000
FUSEADDR = 0x00820004
FUSEWDATA = 0x0082000C
EN_SW_OVERRIDE = 0x00820040
DEBUGCTRL = 0x00820060
RWL_BIT = 1 << 1
CRC_STATUS = 0x00820070
EFP = 0x00820078
DFP = 0x0082007C
DSOV = 0x00820084
FUSEWDATA_PLM = 0x008200F4
FUSECTRL_PLM = 0x008200F8
FUSEOPT_PLM = 0x008200FC
WDATA_WR_SECURE = 0x0082048C
RESENSE_DISABLE = 0x00821058
SBFE = 0x00821108
CMD_IDLE = 0x0
CMD_SENSE_CTRL = 0x3
STATE_MASK = 0x1F << 16
STATE_IDLE = 4 << 16
MAP_BYTES = 0x822000

WATCH = [("FUSECTRL", FUSECTRL), ("CRC_STATUS", CRC_STATUS), ("DSOV", DSOV),
         ("EFP", EFP), ("DISABLE_FUSE_PROGRAM", DFP), ("SBFE", SBFE),
         ("EN_SW_OVERRIDE", EN_SW_OVERRIDE), ("RESENSE_DISABLE", RESENSE_DISABLE),
         ("FUSEWDATA_PLM", FUSEWDATA_PLM), ("FUSECTRL_PLM", FUSECTRL_PLM),
         ("FUSEOPT_PLM", FUSEOPT_PLM), ("WDATA_WR_SECURE", WDATA_WR_SECURE),
         ("DEBUGCTRL", DEBUGCTRL), ("FUSEADDR", FUSEADDR), ("FUSEWDATA", FUSEWDATA)]


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


def snap(bar):
    return {n: bar.rd(o) for n, o in WATCH}


def show(title, s, before=None):
    print(title)
    for n, _ in WATCH:
        mark = ""
        if before is not None and before[n] != s[n]:
            mark = "   <- was 0x%08X" % before[n]
        print("  %-22s 0x%08X%s" % (n, s[n], mark))


def poll_idle(bar, ms):
    end = time.monotonic() + ms / 1000.0
    while time.monotonic() < end:
        if (bar.rd(FUSECTRL) & STATE_MASK) == STATE_IDLE:
            return True
        time.sleep(0.001)
    return False


def window_checks(s):
    return [
        ("FUSECTRL IDLE", (s["FUSECTRL"] & STATE_MASK) == STATE_IDLE),
        ("CRC_STATUS=0x55", s["CRC_STATUS"] == 0x55),
        ("DSOV=0 (glitch window)", s["DSOV"] == 0),
        ("RESENSE_DISABLE=0", s["RESENSE_DISABLE"] == 0),
        ("DEBUGCTRL.RWL=0", (s["DEBUGCTRL"] & RWL_BIT) == 0),
        ("FUSEWDATA_PLM open (latch)", s["FUSEWDATA_PLM"] == 0xFFFFFFFF),
        ("FUSECTRL_PLM open", s["FUSECTRL_PLM"] == 0xFFFFFFFF),
    ]


def clear_sbfe(bar):
    s = snap(bar)
    show("=== state ===", s)
    if s["DSOV"] != 0 or s["EFP"] != 1:
        print("ABORT: need DSOV=0 and EFP=1 (run --confirm sense first).")
        return 1
    if s["SBFE"] == 0:
        print("SBFE already 0; nothing to do.")
        return 0
    bar.wr(EN_SW_OVERRIDE, 1)
    if (bar.rd(EN_SW_OVERRIDE) & 1) != 1:
        print("ABORT: EN_SW_OVERRIDE did not stick.")
        return 1
    bar.wr(SBFE, 0)
    rb = bar.rd(SBFE)
    print("SBFE write 0 -> readback 0x%X  %s" % (rb, "OK" if rb == 0 else "FAILED"))
    return 0 if rb == 0 else 1


def main():
    ap = argparse.ArgumentParser(description="SENSE_CTRL arm (no burn)")
    ap.add_argument("--bdf", required=True)
    ap.add_argument("--confirm", action="store_true", help="issue SENSE_CTRL (else dry-run)")
    ap.add_argument("--clear-sbfe", action="store_true", help="shadow-write SBFE=0 after sense")
    args = ap.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print("Requires Linux + sudo")
        return 2

    bar = Bar0(args.bdf)
    try:
        if bar.rd(BOOT0) == 0xFFFFFFFF:
            print("ABORT: BAR0 reads 0xFFFFFFFF (asleep / decode off / off bus).")
            return 1
        if args.clear_sbfe:
            return clear_sbfe(bar)

        before = snap(bar)
        show("=== before ===", before)
        if before["EFP"] == 1 and before["DSOV"] == 0:
            print("\nEFP=1 and DSOV=0 already: armed. Nothing to do.")
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
        if not args.confirm:
            print("\nDRY-RUN: nothing written. Add --confirm to issue SENSE_CTRL.")
            return 0
        try:
            resp = input("Type SENSE to issue FUSECTRL=3: ")
        except EOFError:
            resp = ""
        if resp.strip() != "SENSE":
            print("ABORT: not confirmed. Nothing written.")
            return 1

        bar.wr(FUSEWDATA, 0)
        if bar.rd(FUSEWDATA) != 0:
            print("ABORT: FUSEWDATA did not read back 0 (0x%08X). No command issued."
                  % bar.rd(FUSEWDATA))
            return 1
        bar.wr(FUSECTRL, CMD_IDLE)
        bar.wr(FUSECTRL, CMD_SENSE_CTRL)
        idle = poll_idle(bar, 2000)
        time.sleep(0.01)
        after = snap(bar)
        print()
        show("=== after SENSE_CTRL ===", after, before)
        if not idle:
            print("\nSTOP: controller did not return to IDLE. Do nothing else; save this output.")
            return 1
        if after["DSOV"] != 0:
            print("\nWINDOW LOST: DSOV=1 after sense. Nothing burned. Power off, re-glitch.")
            return 1
        if after["CRC_STATUS"] != 0x55:
            print("\nSTOP: CRC_STATUS changed. Do nothing else; save this output.")
            return 1
        if after["EFP"] != 1:
            print("\nSTOP: EFP still 0 -- SENSE_CTRL did not arm (wrong cmd code?).")
            return 1
        print("\nARMED: DSOV=0, EFP=1.")
        if after["SBFE"] != 0:
            print("SBFE=0x%X -> next: --clear-sbfe" % after["SBFE"])
        print("Then: sw_override.py, open_wdata_plm.py, ff_burn.py dry-run.")
        return 0
    finally:
        bar.close()


if __name__ == "__main__":
    sys.exit(main())
