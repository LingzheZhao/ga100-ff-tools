#!/usr/bin/env python3
"""Read-only GA100 defect-mask read. O_RDONLY + PROT_READ: cannot write the GPU.

  sudo python3 planner/read_defects.py 0000:01:00.0 > defects.json
Checks FUSECTRL, BOOT0, GFW (0x118234), and every read for PRI poison
(0xBADxxxxx) or dead BAR0 (0xFFFFFFFF) before emitting JSON.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import Bar0, Bar0Abort, GA100_BOOT0  # noqa: E402

REGS = [
    ("OPT_GPC_DEFECTIVE", 0x8205C4),
    ("OPT_FBP_DEFECTIVE", 0x8205CC),
    ("OPT_FBPA_DEFECTIVE", 0x8205D0),
    ("OPT_FBIO_DEFECTIVE", 0x8205D4),
    ("OPT_PES_DEFECTIVE", 0x820698),
    ("OPT_ROP_L2_DEFECTIVE", 0x8205E8),
    ("OPT_NVLINK_DEFECTIVE", 0x82068C),
    ("OPT_PES_DISABLE", 0x820690),
    ("OPT_ROP_L2_DISABLE", 0x8202C4),
    ("CTRL_OPT_GPC", 0x82081C),
    ("EN_SW_OVERRIDE", 0x820040),
    ("DISABLE_SW_OVERRIDE_STATUS", 0x820084),
] + [("OPT_TPC_GPC%d_DEFECTIVE" % i, o) for i, o in enumerate(
    (0x8205C8, 0x820508, 0x82050C, 0x820514, 0x820564, 0x8205AC, 0x820B84, 0x820B80))
] + [("FUSE_CTRL_OPT_TPC_GPC%d" % i, 0x820838 + 4 * i) for i in range(8)]


def read_with_bar(bar, bdf):
    health = bar.check_health_first(require_idle=False, require_gfw=True)
    if health["boot0"] != GA100_BOOT0:
        print("WARNING: PMC_BOOT_0=0x%08X, expected 0x%08X (GA100)"
              % (health["boot0"], GA100_BOOT0), file=sys.stderr)
    regs = [
        {"name": n, "offset": "0x%06X" % o, "value": "0x%08X" % bar.rd_checked(o, n)}
        for n, o in REGS
    ]
    return {
        "bdf": bdf,
        "boot0": "0x%08X" % health["boot0"],
        "gfw": "0x%08X" % health["gfw"],
        "fusectrl": "0x%08X" % health["fusectrl"],
        "registers": regs,
    }


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: sudo python3 planner/read_defects.py <BDF>")
    bdf = sys.argv[1]
    try:
        bar = Bar0(bdf, read_only=True)
    except Bar0Abort as exc:
        sys.exit("ABORT: %s (keep nvidia driver unloaded; enable memory decode with "
                 "`setpci -s %s COMMAND=0x0002:0x0002` if BAR0 reads 0xFFFFFFFF)" % (exc, bdf))
    try:
        out = read_with_bar(bar, bdf)
    except Bar0Abort as exc:
        sys.exit("ABORT: %s (keep nvidia driver unloaded; enable memory decode with "
                 "`setpci -s %s COMMAND=0x0002:0x0002` if BAR0 reads 0xFFFFFFFF)" % (exc, bdf))
    finally:
        bar.close()
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
