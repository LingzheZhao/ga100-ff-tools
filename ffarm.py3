#!/usr/bin/env python3
"""Experimental GA100 volatile arming. Offline description unless --arm is given.

Requires adjacent ffburn.py3. No fuse programming, reset or voltage control.
Hardware execution is a human-only operation; see AGENTS.md and ARMING.md.
"""
import argparse
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
from pathlib import Path
import re
import signal
import struct
import sys

loader = SourceFileLoader('ga100_arm_support', str(Path(__file__).resolve().with_name('ffburn.py3')))
b = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(b)

# Exact pairs only. This adapter cannot address data, rows, or programming commands.
WRITES = ((b.CTRL, b.CMD_SENSE), (b.SW, 1), (b.SBFE, 0), (b.WDATA_SECURE, 0))
REGISTERS = {'FUSECTRL': b.CTRL, 'DEBUGCTRL': b.DEBUG, 'CRC_STATUS': b.CRC,
             'DSOV': b.DSOV, 'EFP': b.EFP, 'SBFE': b.SBFE,
             'EN_SW_OVERRIDE': b.SW, 'WDATA_WR_SECURE': b.WDATA_SECURE,
             'FUSEWDATA_PLM': b.WDATA_PLM, 'FUSECTRL_PLM': b.CTRL_PLM,
             'FUSEOPT_PLM': 0x8200fc, 'RESENSE_DISABLE': 0x821058, 'PMC_BOOT_0': 0}
# Observed on hardware: sensing restores RESENSE_DISABLE to its fused value (1), so
# a window allows one sense. A second one cannot restore EFP; require a fresh glitch.
RESENSE_DISABLE = 0x821058


class ArmBar(b.LinuxBar):
    def wr(self, offset, value):
        b.require(type(offset) is int and type(value) is int and
                  (offset, value) in WRITES, 'Arming adapter rejects this write')
        self.check_device()
        struct.pack_into('<I', self.mm, offset, value)


def snapshot(ctl):
    return {name: ctl.rd(offset, plm=name.endswith('_PLM'))
            for name, offset in REGISTERS.items()}


def guards(ctl, require_efp=False):
    ctl.io.check_device()
    b.require(ctl.idle(), 'Controller is not IDLE')
    b.require(ctl.rd(b.DEBUG) == 0, 'DEBUGCTRL must be zero')
    b.require(ctl.rd(b.CRC) == 0x55, 'CRC_STATUS must be 0x55')
    b.require(ctl.rd(b.DSOV) == 0, 'DSOV must remain zero; stop')
    for offset in (b.CTRL_PLM, 0x8200fc):
        b.require(ctl.rd(offset, plm=True) == 0xffffffff, 'Controller/option PLM is not open')
    b.require(ctl.rd(0) != 0, 'GPU boot register is zero/inaccessible')
    b.require(ctl.rd(b.EFP) in ((1,) if require_efp else (0, 1)), 'EFP did not enable or is invalid')


def run(io, journal):
    """Injected I/O only; CLI supplies a locked, explicitly selected BAR."""
    ctl = b.Controller(io)
    attempted = []
    try:
        journal('arming-start', registers=snapshot(ctl))
        guards(ctl)
        # Already enabled: avoid unnecessary re-sensing and its shadow changes.
        if ctl.rd(b.EFP) == 0:
            b.require(ctl.rd(RESENSE_DISABLE) == 0,
                      'RESENSE_DISABLE is set (sense already used this window); re-glitch')
            journal('write-intent', offset=b.CTRL, value=b.CMD_SENSE)
            guards(ctl)
            b.require(ctl.rd(RESENSE_DISABLE) == 0, 'RESENSE_DISABLE changed after intent')
            attempted.append((b.CTRL, b.CMD_SENSE))
            io.wr(b.CTRL, b.CMD_SENSE)
            ctl.wait(1)
            journal('after-sense', registers=snapshot(ctl))
            guards(ctl, require_efp=True)
        for offset, value in WRITES[1:]:
            guards(ctl, require_efp=True)
            if offset != b.SW:
                b.require(ctl.rd(b.SW) == 1, 'Software override did not remain enabled')
            journal('write-intent', offset=offset, value=value)
            guards(ctl, require_efp=True)
            if offset != b.SW:
                b.require(ctl.rd(b.SW) == 1, 'Software override changed after intent')
            attempted.append((offset, value))
            io.wr(offset, value)
            actual = ctl.rd(offset)
            journal('write-readback', offset=offset, expected=value, actual=actual)
            b.require(actual == value, 'Shadow write did not stick; stop')
        ctl.ready()
        result = {'schema': 'ga100-public-ff-arm-result-v1',
                  'status': 'register_prerequisites_verified',
                  'registers': snapshot(ctl), 'writes_attempted': attempted,
                  'fuses_burned': False, 'hardware_qualification_established': False,
                  'plan_or_baseline_verified': False}
        journal('arming-complete', **result)
        return result
    except BaseException as exc:
        try:
            journal('arming-failed', error=str(exc), writes_attempted=attempted,
                    stop_without_retry=True)
        except BaseException:
            pass
        raise  # No cleanup MMIO, retries, or automatic programming.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true', help='Explicitly perform volatile setup on the selected card')
    parser.add_argument('--bdf', help='Full PCI BDF; required with --arm')
    parser.add_argument('--journal', help='New durable journal; required with --arm')
    args = parser.parse_args(argv)
    if not args.arm:
        b.require(not args.bdf and not args.journal, '--bdf/--journal require --arm')
        print(json.dumps({'offline_only': True, 'writes': WRITES,
                          'sense_only_if_efp_zero': True,
                          'instructions': 'See ARMING.md; no hardware accessed.'}, indent=2))
        return 0
    b.require(args.bdf and re.fullmatch(r'[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[01][0-9a-fA-F]\.[0-7]', args.bdf),
              'Provide a full explicit PCI BDF')
    b.require(args.journal, '--arm requires a new --journal')
    b.require(sys.platform == 'linux', 'Live arming requires Linux')
    journal = b.Journal(args.journal)
    io = None
    try:
        journal('device-open-intent', bdf=args.bdf.lower())
        io = ArmBar(args.bdf.lower())
        result = run(io, journal)
        print(json.dumps(dict(result, bdf=args.bdf.lower()), indent=2))
        return 0
    finally:
        try:
            if io is not None:
                io.close()
        finally:
            journal.close()


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Signal %d; stop without retry' % signum)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyboardInterrupt, struct.error) as exc:
        print('STOP: %s: %s' % (type(exc).__name__, exc), file=sys.stderr)
        raise SystemExit(1)
