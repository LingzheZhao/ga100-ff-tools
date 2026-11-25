"""Hardened GA100 BAR0 MMIO and fuse-controller access helpers.

Safety invariants enforced for every live GPU script in ga100-ff-tools:
  1. Single aligned 32-bit MMIO reads/writes via memoryview(...).cast("I") —
     never struct.pack_into (which zeroes the target slot before packing).
  2. Fail-fast on FUSECTRL first, NVIDIA PRI poison (0xBAD0xxxx..0xBADFxxxx),
     dead BAR0 (0xFFFFFFFF on non-PLM registers), GFW not ready (0x118234 low
     byte != 0xFF), or poll timeout — zero extra register reads and zero
     finally-block register writes after any error.
  3. PCI vendor/device check (NVIDIA GA100 CMP 170HX 10de:20c2 / A100 10de:20b5)
     before opening resource0 so a BDF typo cannot touch another PCI device.
  4. Read-only mode opens resource0 with O_RDONLY + PROT_READ and refuses wr().
"""
import hashlib
import mmap
import os
import time

MAP_BYTES = 0x822000

BOOT0 = 0x00000000
GA100_BOOT0 = 0x170000A1
GFW_BOOT = 0x00118234

FUSECTRL = 0x00820000
FUSEADDR = 0x00820004
FUSERDATA = 0x00820008
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
CMD_READ = 0x1
CMD_WRITE = 0x2
CMD_SENSE_CTRL = 0x3
STATE_MASK = 0x1F << 16
STATE_IDLE = 4 << 16

FF_START = 222
FF_END = 487
DIE_ID_START = 8
DIE_ID_END = 15
FORBIDDEN_BLOCKS = {(2, 37), (2, 38)}

ALLOWED_PCI_IDS = {
    (0x10DE, 0x20C2),  # CMP 170HX 8GB
    (0x10DE, 0x2082),  # CMP 170HX 10GB
    (0x10DE, 0x20B5),  # A100 PCIe 80GB
    (0x10DE, 0x20B0),  # A100 SXM4 40GB
    (0x10DE, 0x20B2),  # A100 SXM4 80GB
    (0x10DE, 0x20F1),  # A100 PCIe 40GB
}


class Bar0Abort(RuntimeError):
    """Raised immediately on poison, dead BAR0, non-IDLE controller, or timeout."""


def is_poisoned(val):
    """True for any NVIDIA PRI error sentinel 0xBAD0xxxx..0xBADFxxxx."""
    return ((val >> 20) & 0xFFF) == 0xBAD


def is_idle(fusectrl):
    return not is_poisoned(fusectrl) and fusectrl != 0xFFFFFFFF and (fusectrl & STATE_MASK) == STATE_IDLE


def gfw_ready(gfw):
    return not is_poisoned(gfw) and gfw != 0xFFFFFFFF and (gfw & 0xFF) == 0xFF


def verify_pci_device(bdf):
    """Confirm sysfs BDF is an NVIDIA GA100 GPU before opening resource0."""
    dev = "/sys/bus/pci/devices/%s" % bdf
    try:
        with open(dev + "/vendor", encoding="ascii") as f:
            vendor = int(f.read().strip(), 16)
        with open(dev + "/device", encoding="ascii") as f:
            device = int(f.read().strip(), 16)
    except OSError as exc:
        raise Bar0Abort("cannot inspect PCI device %s: %s" % (bdf, exc)) from exc
    if (vendor, device) not in ALLOWED_PCI_IDS:
        raise Bar0Abort("PCI device %s is %04x:%04x, not a supported GA100 GPU"
                        % (bdf, vendor, device))
    return vendor, device


def die_id_hash(rows_8_to_15):
    joined = ",".join("0x%08X" % (v & 0xFFFFFFFF) for v in rows_8_to_15)
    return hashlib.sha256(joined.encode("ascii")).hexdigest()[:16]


class Bar0:
    """Single-DWORD BAR0 accessor with fail-fast poison/timeout guards."""

    def __init__(self, bdf=None, read_only=False, mm=None, verify_pci=True):
        self.bdf = bdf
        self.read_only = bool(read_only)
        self._owns_mm = mm is None
        self.fd = None
        if mm is not None:
            self.mm = mm
            return
        if not bdf:
            raise ValueError("bdf is required when mm is not provided")
        if verify_pci:
            verify_pci_device(bdf)
        path = "/sys/bus/pci/devices/%s/resource0" % bdf
        flags = (os.O_RDONLY if self.read_only else (os.O_RDWR | os.O_SYNC)) | os.O_CLOEXEC
        prot = mmap.PROT_READ if self.read_only else (mmap.PROT_READ | mmap.PROT_WRITE)
        self.fd = os.open(path, flags)
        try:
            self.mm = mmap.mmap(self.fd, MAP_BYTES, flags=mmap.MAP_SHARED, prot=prot)
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def rd(self, off):
        if off & 3:
            raise ValueError("unaligned BAR0 read offset 0x%X" % off)
        mv = memoryview(self.mm)[off:off + 4].cast("I")
        try:
            return int(mv[0])
        finally:
            mv.release()

    def rd_checked(self, off, name=None, allow_all_ones=False):
        val = self.rd(off)
        label = name or ("0x%06X" % off)
        if is_poisoned(val):
            raise Bar0Abort("PRI poison reading %s: 0x%08X (STOP immediately)" % (label, val))
        if not allow_all_ones and val == 0xFFFFFFFF:
            raise Bar0Abort("BAR0 dead reading %s: 0xFFFFFFFF (D3 / decode off / off bus)" % label)
        return val

    def wr(self, off, val):
        if self.read_only:
            raise PermissionError("refused BAR0 write to 0x%06X on read-only mapping" % off)
        if off & 3:
            raise ValueError("unaligned BAR0 write offset 0x%X" % off)
        if not isinstance(val, int) or val < 0 or val > 0xFFFFFFFF:
            raise ValueError("32-bit BAR0 write value out of range: %r" % (val,))
        mv = memoryview(self.mm)[off:off + 4].cast("I")
        try:
            mv[0] = val
        finally:
            mv.release()

    def check_health_first(self, require_idle=True, require_gfw=True):
        """Read FUSECTRL first, then BOOT0 and GFW; abort immediately on any fault."""
        fc = self.rd_checked(FUSECTRL, "FUSECTRL")
        if require_idle and not is_idle(fc):
            raise Bar0Abort("FUSECTRL not IDLE: 0x%08X (STOP immediately)" % fc)
        boot0 = self.rd_checked(BOOT0, "BOOT0")
        gfw = self.rd_checked(GFW_BOOT, "GFW_BOOT(0x118234)")
        if require_gfw and not gfw_ready(gfw):
            raise Bar0Abort("GFW boot not complete: 0x118234=0x%08X (low byte != 0xFF; STOP)" % gfw)
        return {"fusectrl": fc, "boot0": boot0, "gfw": gfw}

    def poll_idle(self, timeout_ms=1000, sleep_s=0.001):
        """Poll FUSECTRL until IDLE. Aborts immediately on poison/0xFFFFFFFF or timeout."""
        deadline = time.monotonic() + timeout_ms / 1000.0
        last = None
        while True:
            fc = self.rd_checked(FUSECTRL, "FUSECTRL")
            if (fc & STATE_MASK) == STATE_IDLE:
                return fc
            last = fc
            if time.monotonic() >= deadline:
                raise Bar0Abort("FUSECTRL did not return to IDLE within %d ms (last=0x%08X; STOP)"
                                % (timeout_ms, last))
            if sleep_s > 0:
                time.sleep(sleep_s)

    def read_row(self, row, timeout_ms=1000):
        """Non-destructive CMD_READ of a single physical fuse row. Never writes FUSEWDATA."""
        if not (0 <= row <= 511):
            raise ValueError("fuse row out of range 0..511: %d" % row)
        fc = self.rd_checked(FUSECTRL, "FUSECTRL")
        if not is_idle(fc):
            raise Bar0Abort("FUSECTRL not IDLE before CMD_READ row %d: 0x%08X" % (row, fc))
        self.wr(FUSECTRL, CMD_IDLE)
        self.wr(FUSEADDR, row)
        self.wr(FUSECTRL, CMD_READ)
        self.poll_idle(timeout_ms)
        # Raw fuse rows can legitimately hold any 32-bit pattern (including 0xFFFFFFFF or 0xBADxxxxx).
        return self.rd(FUSERDATA)

    def read_die_id(self, timeout_ms=1000):
        """Read raw rows 8..15 (die ID) via CMD_READ; returns (hex_list, 16-char hash)."""
        vals = [self.read_row(r, timeout_ms=timeout_ms) for r in range(DIE_ID_START, DIE_ID_END + 1)]
        return ["0x%08X" % v for v in vals], die_id_hash(vals)

    def close(self):
        if self._owns_mm and self.mm is not None:
            self.mm.close()
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
