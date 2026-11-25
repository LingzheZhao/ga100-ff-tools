#!/usr/bin/env python3
"""Read-only GA100 defect-mask read. O_RDONLY + PROT_READ: cannot write the GPU.

NOTE: Because O_RDONLY cannot issue CMD_READ for die-ID rows 8-15, standalone
read_defects.py output has NO die-ID binding. For ffcard.py derive/verify, prefer
the unified capture from planner/ff_dump.py (which captures defects, shadows,
FF rows, and die-ID rows 8-15 in one single-card session).

  sudo python3 planner/read_defects.py 0000:01:00.0 > defects.json
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import Bar0, Bar0Abort, DEFECT_REGS  # noqa: E402

REGS = list(DEFECT_REGS) + [
    ("CTRL_OPT_GPC", 0x82081C),
    ("EN_SW_OVERRIDE", 0x820040),
    ("DISABLE_SW_OVERRIDE_STATUS", 0x820084),
] + [("FUSE_CTRL_OPT_TPC_GPC%d" % i, 0x820838 + 4 * i) for i in range(8)]


def read_with_bar(bar, bdf):
    health = bar.check_health_first(require_idle=True, require_gfw=True)
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
