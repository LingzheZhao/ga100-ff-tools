#!/usr/bin/env python3
"""GA100 public-plan burner. Offline review by default; explicit live opt-in.

Use at your own risk. Manually double-check every burn plan before execution.

Consumes adjacent ffplan.py3's saved plans and their original evidence. No
voltage, reset, GPIO, override, SENSE, ROM or PHY setup is performed. The operator
must establish and maintain the externally qualified programming conditions.
"""
import argparse
import datetime
import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
import mmap
import os
from pathlib import Path
import signal
import struct
import sys
import time

CTRL, ADDR, RDATA, WDATA = 0x820000, 0x820004, 0x820008, 0x82000c
DEBUG, CRC, EFP, DSOV = 0x820060, 0x820070, 0x820078, 0x820084
SW, WDATA_SECURE, SBFE = 0x820040, 0x82048c, 0x821108
WDATA_PLM, CTRL_PLM = 0x8200f4, 0x8200f8
MAP_SIZE = 0x822000

# Fuse-controller command field. SENSE is named for protocol completeness;
# these public adapters intentionally reject it.
CMD_IDLE = 0x0
CMD_READ = 0x1
CMD_WRITE = 0x2
CMD_SENSE = 0x3
CMD_MASK = 0x3


def require(ok, message):
    if not ok:
        raise ValueError(message)


def load_planner():
    path = Path(__file__).resolve().with_name('ffplan.py3')
    loader = SourceFileLoader('public_ffburn_planner', str(path))
    module = module_from_spec(spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module, hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(baseline, plan_path, repeat=None, defects=None, bdf=None):
    planner, planner_hash = load_planner()
    plan = json.loads(Path(plan_path).read_text())
    require(plan.get('schema') == 'ga100-public-ff-plan-v2', 'Expected public planner v2 schema')
    planner.simulate(baseline, plan, repeat, defects)  # Full regeneration, hashes and replay.
    evidence = planner.load_capture(baseline, repeat, defects)
    require(evidence['sources'] == plan['input_files_sha256'], 'Input evidence changed during validation')
    rows = evidence['rows']
    require(rows is not None and set(rows) == set(range(512)),
            'Burner requires two complete matching 512-row observations, including IFF')
    if bdf is not None:
        require(planner.normalize_bdf(bdf) == plan['bdf'], 'Selected BDF differs from the plan')
    require(all(222 <= r['row'] <= 487 for r in plan['records']), 'Burner supports FF main-array rows 222–487 only')
    return {'plan': plan, 'rows': [rows[i] for i in range(512)], 'planner_sha256': planner_hash}


def review(context):
    plan = context['plan']
    return {'schema': 'ga100-public-ff-burn-review-v1', 'offline_only': True,
            'bdf': plan['bdf'], 'plan_id': plan['plan_id'], 'features': plan['features'],
            'record_count': len(plan['records']), 'records': plan['records'],
            'logical_validation_passed': True, 'hardware_eligibility_established': False,
            'planner_sha256': context['planner_sha256'],
            'limitations': plan['limitations'],
            'setup': 'Requires an already established burn window and qualified external supply; no setup writes are performed.'}


class Journal:
    """Exclusive durable log; never append to an earlier attempt or resume it."""
    def __init__(self, path):
        self.file = None
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            self.file = os.fdopen(fd, 'w')
            self.file.flush()
            os.fsync(self.file.fileno())
            parent = os.open(Path(path).resolve().parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        except BaseException:
            if self.file is not None:
                self.file.close()
            else:
                os.close(fd)
            raise

    def __call__(self, event, **data):
        entry = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'event': event, **data}
        self.file.write(json.dumps(entry, sort_keys=True)+'\n')
        self.file.flush()
        os.fsync(self.file.fileno())

    def close(self):
        self.file.close()


class LinuxBar:
    """Restricted ports only; shared advisory lock with public capture.py3."""
    def __init__(self, bdf, allow_program=False):
        self.allow_program = allow_program
        require(sys.platform == 'linux', 'Live operations require Linux')
        import fcntl
        self.bdf = bdf
        self.dev = Path('/sys/bus/pci/devices')/bdf
        self.fd = self.mm = self.lock = None
        try:
            self.lock = open('/run/lock/ga100-public-capture-'+bdf.replace(':', '_'), 'a')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check_device()
            start, end, flags = [int(v,16) for v in (self.dev/'resource').read_text().splitlines()[0].split()]
            require(flags & 0x200 and start and end >= start and end-start+1 >= MAP_SIZE,
                    'BAR0 must be an available memory resource of sufficient size')
            self.fd = os.open(self.dev/'resource0', os.O_RDWR | os.O_SYNC | os.O_CLOEXEC)
            self.mm = mmap.mmap(self.fd, MAP_SIZE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        except BaseException:
            self.close()
            raise

    def check_device(self):
        require(not (self.dev/'driver').exists() and not (self.dev/'driver').is_symlink(),
                'Target has a bound driver; stop')
        with (self.dev/'config').open('rb', buffering=0) as f:
            config = f.read(64)
        require(len(config) == 64, 'Incomplete PCI configuration')
        vendor, device = struct.unpack_from('<HH', config)
        require(vendor == 0x10de and device in (0x20c2, 0x2080),
                'Expected selected CMP 20c2 or glitch 2080 identity')
        require(struct.unpack_from('<H', config, 4)[0] & 2, 'PCI memory decode is not enabled')

    def rd(self, offset):
        require(type(offset) is int and offset % 4 == 0 and 0 <= offset <= MAP_SIZE-4, 'Invalid MMIO read')
        return struct.unpack_from('<I', self.mm, offset)[0]

    def wr(self, offset, value):
        require(type(value) is int and 0 <= value <= 0xffffffff, 'Invalid MMIO value')
        require((offset == ADDR and 0 <= value < 512) or
                (offset == CTRL and value in (CMD_IDLE, CMD_READ, CMD_WRITE)) or offset == WDATA,
                'Only main-array address, IDLE/READ/WRITE commands and WDATA are permitted')
        require(self.allow_program or not (offset == WDATA or (offset == CTRL and value == CMD_WRITE)),
                'Preflight adapter forbids program-data and CMD_WRITE writes')
        self.check_device()
        struct.pack_into('<I', self.mm, offset, value)

    def close(self):
        try:
            if self.mm is not None:
                self.mm.close()
                self.mm = None
        finally:
            try:
                if self.fd is not None:
                    os.close(self.fd)
                    self.fd = None
            finally:
                if self.lock is not None:
                    self.lock.close()
                    self.lock = None


class Controller:
    def __init__(self, io):
        self.io = io

    def rd(self, offset, raw=False, plm=False):
        value = self.io.rd(offset)
        require(type(value) is int and 0 <= value <= 0xffffffff, 'Invalid MMIO read value')
        require(value & 0xffff0000 != 0xbadf0000, 'PRI error at 0x%x' % offset)
        require(raw or plm or value != 0xffffffff, 'Inaccessible all-ones register at 0x%x' % offset)
        return value

    def idle(self):
        return ((self.rd(CTRL) >> 16) & 31) == 4

    def ready(self):
        self.io.check_device()
        require(self.idle(), 'Controller is not IDLE')
        require(self.rd(DEBUG) == 0, 'DEBUGCTRL must be zero; RIR/debug mode is unsupported')
        require(self.rd(CRC) == 0x55, 'CRC_STATUS must be 0x55')
        require(self.rd(DSOV) == 0, 'DSOV must be zero; burn window is not ready')
        require(self.rd(EFP) == 1, 'Fuse programming is not enabled')
        require(self.rd(SBFE) == 0, 'Secured-burn feature must be disabled')
        require(self.rd(SW) == 1, 'Software override must already be enabled')
        require(self.rd(WDATA_SECURE) == 0, 'Fuse WDATA security must already be disabled')
        require(self.rd(WDATA_PLM, plm=True) == 0xffffffff, 'FUSEWDATA_PLM is not open')
        require(self.rd(CTRL_PLM, plm=True) == 0xffffffff, 'FUSECTRL_PLM is not open')
        require(self.rd(0) != 0, 'GPU boot register is zero/inaccessible')

    def wait(self, timeout):
        deadline = time.monotonic()+timeout
        while not self.idle():
            if time.monotonic() >= deadline:
                raise TimeoutError('Fuse command timed out; stop without retry')
            time.sleep(0.001)

    def read_row(self, row):
        require(type(row) is int and 0 <= row < 512, 'Invalid physical row')
        self.ready()
        self.io.wr(CTRL, CMD_IDLE)
        self.io.wr(ADDR, row)
        require(self.rd(ADDR) == row, 'Row address did not latch')
        self.io.wr(CTRL, CMD_READ)
        self.wait(1)
        self.ready()
        require(self.rd(ADDR) == row, 'Row address changed during read')
        return self.rd(RDATA, raw=True)

    def read_all(self):
        deadline = time.monotonic()+60
        passes = []
        for _ in range(2):
            values = []
            for row in range(512):
                require(time.monotonic() < deadline, 'Full-array read exceeded deadline')
                values.append(self.read_row(row))
            passes.append(values)
        require(passes[0] == passes[1], 'Live physical-row passes disagree')
        return passes[0]


def confirm_programming(context):
    """Three exact interactive confirmations; no piped input or automatic bypass."""
    require(sys.stdin.isatty(), 'Programming requires an interactive terminal for three confirmations')
    plan = context['plan']
    count = len(plan['records'])
    print('USE AT YOUR OWN RISK: irreversible OTP programming can permanently damage hardware.')
    print('Manually double-check the card, baseline, defect masks, rows and encoded words before proceeding.')
    print('IRREVERSIBLE FF PROGRAMMING')
    print('Card: %s' % plan['bdf'])
    print('Plan: %s' % plan['plan_id'])
    print('Records: %d; rows: %s' % (count, ', '.join(str(r['row']) for r in plan['records'])))
    prompts = (
        ('1/3 — Type the target BDF: ', plan['bdf']),
        ('2/3 — Type the full plan_id: ', plan['plan_id']),
        ('3/3 — Type BURN %d ROWS to confirm permanent OTP programming: ' % count,
         'BURN %d ROWS' % count),
    )
    for prompt, expected in prompts:
        try:
            answer = input(prompt)
        except EOFError:
            raise ValueError('Confirmation input ended; no programming authorized') from None
        require(answer.strip() == expected, 'Confirmation did not match; no programming authorized')


def run(context, io, journal, execute=False):
    """Injected I/O for tests. Caller supplies and closes the already locked BAR."""
    plan, baseline = context['plan'], context['rows']
    require(not execute or plan['records'], 'No records to program')
    ctl = Controller(io)
    issued, completed = [], []
    try:
        journal('session-start', bdf=plan['bdf'], plan_id=plan['plan_id'],
                planner_sha256=context['planner_sha256'], execute=execute,
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip() if sys.platform == 'linux' else None)
        if execute:
            confirm_programming(context)
            journal('user-confirmed', confirmations=3, bdf=plan['bdf'], plan_id=plan['plan_id'])
        # All live guards and the complete baseline scan happen after user input.
        ctl.ready()
        saved = ctl.rd(ADDR)
        require(0 <= saved < 512, 'Original row address is invalid')
        require(ctl.read_all() == baseline, 'Live full array differs from this card baseline; no resume/retry')
        ctl.ready()
        journal('baseline-matched', physical_rows=512, matching_passes=2)
        expected = list(baseline)
        if execute:
            for record in plan['records']:
                row, value = record['row'], record['word']
                require(222 <= row <= 487 and row < plan['iff_boundary'] and expected[row] == 0,
                        'Record is not a blank FF append row')
                require(0 <= value <= 0xffffffff and value & 32 == 0 and value & 31 in (1,2), 'Invalid FF word')
                journal('program-intent', **record)
                # Check after the durable intent; a slow log write never authorizes stale state.
                require(ctl.read_row(row) == 0, 'Target row is no longer blank')
                ctl.ready()
                require(ctl.rd(ADDR) == row, 'Target address changed before programming')
                io.wr(CTRL, CMD_IDLE)
                io.wr(ADDR, row)
                require(ctl.rd(ADDR) == row, 'Program address did not latch')
                io.wr(WDATA, value)
                # Recheck the burn-window guards after staging WDATA and before CMD_WRITE.
                ctl.ready()
                require(ctl.rd(ADDR) == row, 'Target address changed after staging data')
                issued.append(row)  # Track the command attempt even if the MMIO write raises.
                io.wr(CTRL, CMD_WRITE)
                ctl.wait(5)
                actual = ctl.read_row(row)
                journal('program-readback', row=row, expected=value, actual=actual)
                require(actual == value, 'Program readback mismatch; stop without retry')
                expected[row] = value
                completed.append(row)
            require(ctl.read_all() == expected, 'Post-program full-array verification failed')
        ctl.ready()
        io.wr(ADDR, saved)
        require(ctl.rd(ADDR) == saved, 'Original address restoration failed')
        result = {'schema':'ga100-public-ff-burn-result-v1', 'bdf':plan['bdf'], 'plan_id':plan['plan_id'],
                  'mode':'program' if execute else 'preflight', 'records_verified':len(completed),
                  'program_commands_attempted':len(issued), 'full_array_verified':True,
                  'raw_address_restored':True, 'cold_boot_verified':False,
                  'working_features_verified':False, 'hardware_qualification_established':False}
        journal('session-complete', **result)
        return result
    except BaseException as exc:
        # Never issue cleanup MMIO or retry after an uncertain command.
        try:
            journal('session-failed', error=type(exc).__name__+': '+str(exc),
                    commands_attempted=issued, rows_verified=completed,
                    address_restoration_attempted=False, stop_without_retry=True)
        except BaseException:
            pass  # Preserve the original failure, including a failed journal write.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--repeat', help='Same separate repeat input used by the planner')
    parser.add_argument('--defects', help='Same separate defect input used by the planner')
    parser.add_argument('--bdf', help='Required explicit card selection for live operations; must match plan')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--preflight', action='store_true', help='Live burn-window checks and two raw READ passes; no programming')
    modes.add_argument('--execute-plan', metavar='PLAN_ID', help='Program the exact validated plan after three interactive confirmations; irreversible')
    parser.add_argument('--journal', help='Required new durable journal for any live operation')
    args = parser.parse_args(argv)
    context = prepare(args.baseline, args.plan, args.repeat, args.defects, args.bdf)
    if not (args.preflight or args.execute_plan is not None):
        require(not args.journal, 'Journal is only for live operations')
        print(json.dumps(review(context), indent=2))
        return 0
    require(args.bdf and args.journal, 'Live operations require --bdf and a new --journal')
    if args.execute_plan is not None:
        require(args.execute_plan == context['plan']['plan_id'], '--execute-plan must equal the exact plan_id')
        require(context['plan']['records'], 'No records to program')
    require(sys.platform == 'linux', 'Live operations require Linux')
    journal = Journal(args.journal)  # Reserve and sync before opening the GPU.
    io = None
    try:
        journal('device-open-intent', bdf=context['plan']['bdf'])
        io = LinuxBar(context['plan']['bdf'], allow_program=args.execute_plan is not None)
        result = run(context, io, journal, execute=args.execute_plan is not None)
        print(json.dumps(result, indent=2))
        return 0
    except BaseException as exc:
        if io is None:
            try:
                journal('device-open-failed', error=type(exc).__name__+': '+str(exc))
            except BaseException:
                pass
        raise
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
    except (ValueError, OSError, KeyError, TypeError, IndexError, struct.error, KeyboardInterrupt) as exc:
        print('STOP: %s: %s' % (type(exc).__name__, exc), file=sys.stderr)
        raise SystemExit(1)
