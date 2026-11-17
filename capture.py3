#!/usr/bin/env python3
"""Public-source GA100 option and optional physical-row capture (Python 3.8+).

Standalone; standard library only. No local NVIDIA headers/maps are used.
Default mode uses only PCI config and MMIO reads. --raw adds bounded CMD_READ
requests through the address/control ports, never programming commands.
No overrides, re-sensing, resets, voltage changes or fuse programming.
"""
import argparse
from contextlib import ExitStack
import datetime
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import struct
import sys
import time

BLOG = 'https://blog.kate.land/posts/using-voltage-glitching-to-unlock-the-a100/'
PUBLIC_DATA = 'https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/'
OPTIONS_SOURCE = PUBLIC_DATA + 'ga100-options.json'
CORE_SOURCE = PUBLIC_DATA + 'ga100-core.json'
RAW_SOURCE = 'https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/src/lib.rs'

# Names selected from the blog's FF table; addresses independently checked
# against the PUBLIC ga100-options.json. No chain positions are used as offsets.
OPTIONS = {
    'NV_FUSE_OPT_FBIO_DISABLE': 0x0082036c,
    'NV_FUSE_OPT_FBPA_DISABLE': 0x00820368,
    'NV_FUSE_OPT_GPC_DISABLE': 0x00820350,
    'NV_FUSE_OPT_TPC_GPC0_DISABLE': 0x00820760,
    'NV_FUSE_OPT_TPC_GPC1_DISABLE': 0x00820764,
    'NV_FUSE_OPT_TPC_GPC2_DISABLE': 0x00820768,
    'NV_FUSE_OPT_TPC_GPC3_DISABLE': 0x0082076c,
    'NV_FUSE_OPT_TPC_GPC4_DISABLE': 0x00820770,
    'NV_FUSE_OPT_TPC_GPC5_DISABLE': 0x00820774,
    'NV_FUSE_OPT_TPC_GPC6_DISABLE': 0x00820778,
    'NV_FUSE_OPT_TPC_GPC7_DISABLE': 0x0082077c,
    'NV_FUSE_OPT_PES_DISABLE': 0x00820690,
    'NV_FUSE_OPT_FBP_DISABLE': 0x00820364,
    'NV_FUSE_OPT_ROP_L2_DISABLE': 0x008202c4,
    'NV_FUSE_OPT_NVLINK_DISABLE': 0x00820684,
    'NV_FUSE_OPT_NVLINK_DEFECTIVE': 0x0082068c,
    'NV_FUSE_OPT_DISABLE_GEN3_SPEED': 0x00820250,
    'NV_FUSE_OPT_PCIE_MAGIC_BITS_D': 0x00820520,
    'NV_FUSE_OPT_PCIE_BOOT_GEN23_DISABLE': 0x0082057c,
    'NV_FUSE_OPT_PCIE_BOOT_GEN3_DISABLE': 0x00820580,
    'NV_FUSE_OPT_PCIE_DEVIDA': 0x008204d8,
    'NV_FUSE_OPT_PCIE_DEVIDB': 0x0082056c,
    'NV_FUSE_OPT_SYS_PIPE_DISABLE': 0x008203a4,
    # Also explicitly discussed in the blog's floorsweeping/burn sections.
    'NV_FUSE_OPT_FBP_DEFECTIVE': 0x008205cc,
    'NV_FUSE_OPT_SECURED_BURN_FEATURE_ENABLE': 0x00821108,
    'NV_FUSE_OPT_SECURE_FUSE_WDATA_WR_SECURE': 0x0082048c,
}
# Additional public defect option registers required by the public planner.
DEFECT_OPTIONS = {'NV_FUSE_OPT_FBIO_DEFECTIVE': 8521172,
 'NV_FUSE_OPT_FBPA_DEFECTIVE': 8521168,
 'NV_FUSE_OPT_FBP_DEFECTIVE': 8521164,
 'NV_FUSE_OPT_GPC_DEFECTIVE': 8521156,
 'NV_FUSE_OPT_PES_DEFECTIVE': 8521368,
 'NV_FUSE_OPT_ROP_L2_DEFECTIVE': 8521192,
 'NV_FUSE_OPT_TPC_GPC0_DEFECTIVE': 8521160,
 'NV_FUSE_OPT_TPC_GPC1_DEFECTIVE': 8520968,
 'NV_FUSE_OPT_TPC_GPC2_DEFECTIVE': 8520972,
 'NV_FUSE_OPT_TPC_GPC3_DEFECTIVE': 8520980,
 'NV_FUSE_OPT_TPC_GPC4_DEFECTIVE': 8521060,
 'NV_FUSE_OPT_TPC_GPC5_DEFECTIVE': 8521132,
 'NV_FUSE_OPT_TPC_GPC6_DEFECTIVE': 8522628,
 'NV_FUSE_OPT_TPC_GPC7_DEFECTIVE': 8522624}
OPTIONS.update(DEFECT_OPTIONS)

# Blog-discussed controller/security observations. Names/offsets from public core map.
CORE = {
    'FUSECTRL': 0x00820000,
    'CRC_STATUS': 0x00820070,
    'ENABLE_FUSE_PROGRAM_STATUS': 0x00820078,
    'DISABLE_SW_OVERRIDE_STATUS': 0x00820084,
    'EN_SW_OVERRIDE': 0x00820040,
    'FUSECTRL_PLM': 0x008200f8,
    'FUSEOPT_PLM': 0x008200fc,
    'FUSEWDATA_PLM': 0x008200f4,
    'FUSEDEBUG': 0x00820060,
    'PMC_BOOT_0': 0x00000000,
}
REGISTERS = dict(sorted({**OPTIONS, **CORE}.items()))
MAP_SIZE = max(REGISTERS.values()) + 4
MAP_SHA256 = hashlib.sha256(json.dumps(REGISTERS, sort_keys=True).encode()).hexdigest()


def register_manifest():
    return {name: {'offset': '0x%08x' % off,
                   'offset_source': OPTIONS_SOURCE if name in OPTIONS else CORE_SOURCE,
                   'selection_source': (OPTIONS_SOURCE if name in DEFECT_OPTIONS else
                                        BLOG if name in OPTIONS else CORE_SOURCE)}
            for name, off in REGISTERS.items()}


def validate_bdf(value):
    if not re.fullmatch(r'[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]', value):
        raise ValueError('Use a full BDF such as 0000:01:00.0')
    return value.lower()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sample(rd, values, issues):
    """Fill incrementally so a read error does not discard earlier observations."""
    for name, off in REGISTERS.items():
        value = rd(off)
        values[name] = '0x%08x' % value
        if value & 0xffff0000 == 0xbadf0000:
            issues[name] = 'PRI error response'
        elif value == 0xffffffff and name not in ('FUSECTRL_PLM', 'FUSEOPT_PLM', 'FUSEWDATA_PLM'):
            issues[name] = 'All-ones value: ambiguous/unreadable; not treated as valid fuse data'


FUSECTRL, FUSEADDR, FUSEDATA, FUSEDEBUG = 0x820000, 0x820004, 0x820008, 0x820060
CRC_STATUS = 0x820070

# Fuse-controller command field. SENSE is named for protocol completeness;
# these public adapters intentionally reject it.
CMD_IDLE = 0x0
CMD_READ = 0x1
CMD_WRITE = 0x2
CMD_SENSE = 0x3
CMD_MASK = 0x3


class LinuxBar:
    """Selected-device adapter with only address selection and CMD_READ writes."""
    def __init__(self, dev, writable=False):
        import fcntl
        self.dev, self.writable = dev, writable
        self.fd = None
        self.lock = open('/run/lock/ga100-public-capture-'+dev.name.replace(':', '_'), 'a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = os.open(dev/'resource0', (os.O_RDWR if writable else os.O_RDONLY) | os.O_SYNC)
            prot = mmap.PROT_READ | (mmap.PROT_WRITE if writable else 0)
            self.mm = mmap.mmap(self.fd, MAP_SIZE, flags=mmap.MAP_SHARED, prot=prot)
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
            self.lock.close()
            raise

    def rd(self, offset):
        return struct.unpack_from('<I', self.mm, offset)[0]

    def _write(self, offset, value):
        require(self.writable, 'Read-only adapter cannot issue commands')
        require(not (self.dev/'driver').exists() and not (self.dev/'driver').is_symlink(),
                'A driver bound to the card during capture; stop')
        require(type(value) is int and ((offset == FUSEADDR and 0 <= value < 512)
                                       or (offset == FUSECTRL and value == CMD_READ)),
                'Adapter permits only physical row selection and CMD_READ')
        struct.pack_into('<I', self.mm, offset, value)

    def select_row(self, row):
        self._write(FUSEADDR, row)

    def issue_read(self):
        self._write(FUSECTRL, CMD_READ)

    def restore_address(self, value):
        self._write(FUSEADDR, value)

    def close(self):
        try:
            self.mm.close()
        finally:
            try:
                os.close(self.fd)
            finally:
                self.lock.close()


def checked_read(io, offset, allow_all_ones=False):
    value = io.rd(offset)
    require(type(value) is int and 0 <= value <= 0xffffffff, 'Invalid MMIO word')
    require(value & 0xffff0000 != 0xbadf0000, 'PRI error at 0x%08x' % offset)
    require(allow_all_ones or value != 0xffffffff, 'Inaccessible/ambiguous register at 0x%08x' % offset)
    return value


def controller_idle(io):
    control = checked_read(io, FUSECTRL)
    return ((control >> 16) & 31) == 4 and control & CMD_MASK == CMD_IDLE


def read_rows(io, report, per_row_timeout=0.2, total_timeout=20.0):
    """Two bounded non-programming passes; preserve partial rows and restore address."""
    require(0 < per_row_timeout <= 1 and 0 < total_timeout <= 60, 'Invalid timeout policy')
    require(controller_idle(io), 'Fuse controller must be IDLE before any row command')
    require(checked_read(io, CRC_STATUS) == 0x55, 'CRC_STATUS must be 0x55 before raw reads')
    require(checked_read(io, FUSEDEBUG) == 0, 'FUSEDEBUG is not in the public reference reader\'s normal mode')
    require(checked_read(io, 0) != 0, 'GPU boot register is zero/inaccessible')
    saved = checked_read(io, FUSEADDR)
    require(0 <= saved < 512, 'Unexpected original fuse address')
    report['raw_original_address'] = saved
    deadline = time.monotonic()+total_timeout
    try:
        for _ in range(2):
            rows = []
            report['raw_rows'].append(rows)
            for row in range(512):
                require(time.monotonic() < deadline, 'Physical-row capture exceeded total deadline')
                require(controller_idle(io), 'Controller is not IDLE before row %d' % row)
                require(checked_read(io, FUSEDEBUG) == 0, 'Fuse debug mode changed during capture')
                require(checked_read(io, CRC_STATUS) == 0x55, 'CRC status changed during capture')
                io.select_row(row)
                require(checked_read(io, FUSEADDR) == row, 'Fuse address did not latch for row %d' % row)
                io.issue_read()
                row_deadline = min(deadline, time.monotonic()+per_row_timeout)
                while not controller_idle(io):
                    if time.monotonic() >= row_deadline:
                        raise TimeoutError('Physical row %d timed out' % row)
                    time.sleep(0.001)
                # All-ones can be an actual physical OTP word; do not turn it into a blank.
                value = checked_read(io, FUSEDATA, allow_all_ones=True)
                rows.append('0x%08x' % value)
    finally:
        try:
            io.restore_address(saved)
            require(checked_read(io, FUSEADDR) == saved, 'Original fuse address was not restored')
            report['raw_address_restored'] = True
        except (OSError, ValueError) as exc:
            report['raw_address_restored'] = False
            report['restore_error'] = '%s: %s' % (type(exc).__name__, exc)
    require(report.get('raw_address_restored'), 'Failed to restore original fuse address')
    report['raw_match'] = report['raw_rows'][0] == report['raw_rows'][1]
    report['physical_rows_captured'] = True


def capture_io(io, report, raw=False):
    """Shared capture logic; tests inject an in-memory adapter, never a real device."""
    values, issues = {}, {}
    report['options'].append(values)
    report['read_issues'].append(issues)
    sample(io.rd, values, issues)
    if raw:
        require(not issues, 'Suspect option reads; no physical-row command issued')
        read_rows(io, report)
    values, issues = {}, {}
    report['options'].append(values)
    report['read_issues'].append(issues)
    sample(io.rd, values, issues)
    report['options_match'] = report['options'][0] == report['options'][1]
    report['complete'] = True
    report['ok'] = report['options_match'] and not any(report['read_issues'])
    if raw:
        report['ok'] = report['ok'] and report['raw_match'] and report['raw_address_restored']


def new_report(bdf, raw=False):
    return {
        'schema': 'ga100-public-capture-v1',
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'bdf': bdf, 'non_programming': True, 'mmio_read_only': not raw,
        'raw_requested': raw, 'physical_rows_captured': False,
        'public_map_sha256': MAP_SHA256, 'registers': register_manifest(),
        'raw_protocol_source': RAW_SOURCE,
        'options': [], 'read_issues': [], 'raw_rows': [], 'complete': False, 'ok': False,
        'note': 'Captured observations only; matching reads do not establish programming eligibility or working hardware.',
    }


def capture_device(bdf, raw=False, sysfs=Path('/sys/bus/pci/devices'),
                   boot_file=Path('/proc/sys/kernel/random/boot_id'), bar_factory=None):
    bdf = validate_bdf(bdf)
    report = new_report(bdf, raw)
    try:
        dev = sysfs/bdf
        require(not (dev/'driver').is_symlink() and not (dev/'driver').exists(),
                'Device has a bound driver; unbind only the selected card first')
        with (dev/'config').open('rb', buffering=0) as config:
            cfg = config.read(64)
        require(len(cfg) == 64 and cfg[:4] != b'\xff'*4, 'PCI configuration is inaccessible')
        vendor, device = struct.unpack_from('<HH', cfg)
        require(vendor == 0x10de and device in (0x20c2, 0x2080), 'Expected CMP 170HX 20c2 or GA100 glitch identity 2080')
        require(struct.unpack_from('<H', cfg, 4)[0] & 2,
                'PCI memory decoding is disabled; this script does not change PCI configuration')
        report.update(pci_vendor='0x%04x' % vendor, pci_device='0x%04x' % device,
                      boot_id=boot_file.read_text().strip())
        start, end, flags = [int(v, 16) for v in (dev/'resource').read_text().splitlines()[0].split()]
        require(flags & 0x200 and start and end >= start and end-start+1 >= MAP_SIZE,
                'BAR0 is absent, not a memory resource or too small')
        bar = (bar_factory or LinuxBar)(dev, writable=raw)
        try:
            capture_io(bar, report, raw)
        finally:
            bar.close()
    except KeyboardInterrupt:
        report.update(interrupted=True, complete=False, ok=False, error='Capture interrupted')
    except (OSError, ValueError, IndexError, struct.error) as exc:
        report.update(complete=False, ok=False, error='%s: %s' % (type(exc).__name__, exc))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bdf', nargs='+', help='One or more explicit card BDFs')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('--output', help='Exact JSON filename for one card')
    output.add_argument('--output-dir', default=None, help='One timestamped JSON per card (default: current directory)')
    parser.add_argument('--raw', action='store_true', help='Two physical 512-row READ passes; writes command/address ports only')
    parser.add_argument('--list-registers', action='store_true', help='Print embedded public allowlist; no hardware access')
    args = parser.parse_args(argv)
    if args.list_registers:
        print(json.dumps(register_manifest(), indent=2))
        return 0
    if sys.platform != 'linux':
        parser.error('Capture requires the Linux host containing the card; --list-registers works offline')
    if not args.bdf:
        parser.error('--bdf is required')
    try:
        bdfs = [validate_bdf(bdf) for bdf in args.bdf]
    except ValueError as exc:
        parser.error(str(exc))
    if len(set(bdfs)) != len(bdfs):
        parser.error('Duplicate BDFs requested')
    if args.output and len(bdfs) != 1:
        parser.error('--output accepts one card; use --output-dir for multiple cards')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    directory = Path(args.output_dir or '.')
    if not args.output:
        directory.mkdir(parents=True, exist_ok=True)
    paths = ([Path(args.output)] if args.output else
             [directory / ('public-%s-%s.json' % (bdf.replace(':', '_').replace('.', '_'), stamp))
              for bdf in bdfs])
    # Reserve every destination before touching hardware. Never overwrite a dump.
    status = 0
    with ExitStack() as stack:
        outputs = [stack.enter_context(path.open('x')) for path in paths]
        for bdf, path, out in zip(bdfs, paths, outputs):
            report = capture_device(bdf, raw=args.raw)
            json.dump(report, out, indent=2)
            out.write('\n')
            out.flush()
            print('%s: %s -> %s' % (bdf, 'OK' if report['ok'] else 'INCOMPLETE/UNRELIABLE', path))
            if report.get('interrupted'):
                return 130
            if not report['ok']:
                status = 1
                if 'error' in report:
                    print(report['error'], file=sys.stderr)
    return status


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except OSError as exc:
        print('Capture failed: %s' % exc, file=sys.stderr)
        raise SystemExit(1)
