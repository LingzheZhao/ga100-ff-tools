#!/usr/bin/env python3
"""Read-only PCIe/NVLink fuse shadows and link speed of a GA100. Cannot write the GPU.

BAR0 is mapped O_RDONLY + PROT_READ; PCI config space is read from sysfs. Use it
after a cold boot to check the pcie/nvlink plans (ff_dump.py has no PCIe shadows).

  sudo python3 planner/pcie_state.py 0000:01:00.0          # table, exit 0 when all at target
  sudo python3 planner/pcie_state.py 0000:01:00.0 --json
Memory decode must be on (setpci -s BDF COMMAND=0x0002:0x0002) if BAR0 reads 0xFFFFFFFF.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import Bar0, Bar0Abort  # noqa: E402

# (name, offset, target after the pcie + nvlink plans, or None = report only)
REGS = [
    ("DISABLE_GEN3_SPEED", 0x820250, 0x0),
    ("BOOT_GEN23_DISABLE", 0x82057C, 0x0),
    ("BOOT_GEN3_DISABLE", 0x820580, 0x0),
    ("PCIE_MAGIC_BITS_D", 0x820520, 0x00200000),
    ("OPT_NVLINK_DISABLE", 0x820684, None),
    ("OPT_NVLINK_DEFECTIVE", 0x82068C, None),
    ("DSOV", 0x820084, None),
]
SPEEDS = {1: "2.5GT/s", 2: "5GT/s", 3: "8GT/s", 4: "16GT/s", 5: "32GT/s"}


def pcie_cap(cfg):
    """Offset of the PCI Express capability (ID 0x10) in config space."""
    ptr = cfg[0x34] & 0xFC
    seen = set()
    while ptr and ptr not in seen and ptr + 1 < len(cfg):
        seen.add(ptr)
        if cfg[ptr] == 0x10:
            return ptr
        ptr = cfg[ptr + 1] & 0xFC
    return None


def link(cfg, off):
    v = struct.unpack_from("<H", cfg, off)[0]
    return "%s x%d" % (SPEEDS.get(v & 0xF, "?"), (v >> 4) & 0x3F)


def main():
    ap = argparse.ArgumentParser(description="Read-only GA100 PCIe/NVLink shadows")
    ap.add_argument("bdf")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    dev = "/sys/bus/pci/devices/%s" % args.bdf
    try:
        bar = Bar0(args.bdf, read_only=True)
    except Bar0Abort as exc:
        sys.exit("ABORT: %s" % exc)
    try:
        bar.check_health_first(require_idle=False, require_gfw=False)
        regs = [(n, o, bar.rd_checked(o, n), t) for n, o, t in REGS]
    except Bar0Abort as exc:
        sys.exit("ABORT: %s" % exc)
    finally:
        bar.close()

    with open(dev + "/config", "rb") as f:
        cfg = f.read(256)
    cap = pcie_cap(cfg)
    lnk = {
        "LnkCap": link(cfg, cap + 0x0C) if cap is not None else None,
        "LnkSta": link(cfg, cap + 0x12) if cap is not None else None,
    }
    bad = [n for n, _, v, t in regs if t is not None and v != t]
    if lnk["LnkCap"] is None or not lnk["LnkCap"].startswith("16GT/s"):
        bad.append("LnkCap")
    if args.json:
        print(json.dumps({
            "bdf": args.bdf,
            "link": lnk,
            "ok": not bad,
            "registers": [
                {"name": n, "offset": "0x%06X" % o, "value": "0x%08X" % v,
                 "target": None if t is None else "0x%08X" % t}
                for n, o, v, t in regs
            ],
        }, indent=2))
    else:
        for n, o, v, t in regs:
            print("%-22s 0x%06X  0x%08X  %s" % (
                n, o, v, "-" if t is None else ("OK" if v == t else "want 0x%08X" % t)))
        print("%-22s %s  (target 16GT/s x16)" % ("LnkCap", lnk["LnkCap"]))
        print("%-22s %s  (trained speed; Gen4 needs the driver/gpu-unlock retrain)" %
              ("LnkSta", lnk["LnkSta"]))
        print("PCIe fuses %s" % ("at target" if not bad else "NOT at target: " + ", ".join(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
