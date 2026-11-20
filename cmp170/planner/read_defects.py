#!/usr/bin/env python3
"""Read-only GA100 defect-mask read. O_RDONLY + PROT_READ: cannot write the GPU.

  sudo python3 read_defects.py 0000:01:00.0 > defects.json
Offsets from host_scripts/check.py and cmprir/gpcprobe/gpc_probe.py.
"""
import json
import mmap
import os
import struct
import sys

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

bdf = sys.argv[1]
fd = os.open("/sys/bus/pci/devices/%s/resource0" % bdf, os.O_RDONLY | os.O_CLOEXEC)
m = mmap.mmap(fd, 0x822000, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
boot0 = struct.unpack_from("<I", m, 0)[0]  # PMC_BOOT_0; GA100 = 0x170000A1
if boot0 == 0xFFFFFFFF:
    sys.exit("ABORT: BAR0 reads 0xFFFFFFFF (GPU asleep/D3, memory decode off, "
             "or off the bus). Load the nvidia driver, run nvidia-smi, retry.")
if boot0 != 0x170000A1:
    print("WARNING: PMC_BOOT_0=0x%08X, expected 0x170000A1 (GA100)" % boot0,
          file=sys.stderr)
regs = [{"name": n, "offset": "0x%06X" % o,
         "value": "0x%08X" % struct.unpack_from("<I", m, o)[0]} for n, o in REGS]
m.close()
os.close(fd)
print(json.dumps({"bdf": bdf, "registers": regs}, indent=2))
