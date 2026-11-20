"""Synthetic arming tests; no PCI access."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch
from test_tools import load

a = load('public_arming', Path(__file__).resolve().parents[1]/'ffarm.py3')
b = a.b


class FakeIO:
    def __init__(self):
        self.reg = {b.CTRL: 0xe0040000, b.DEBUG: 0, b.CRC: 0x55,
                    b.DSOV: 0, b.EFP: 0, b.SBFE: 0, b.SW: 0,
                    b.WDATA_SECURE: 1, b.WDATA_PLM: 0xffffff8f,
                    b.CTRL_PLM: 0xffffffff, 0x8200fc: 0xffffffff, a.RESENSE_DISABLE: 0,
                    0: 0x170000a1}
        self.writes = []
        self.after_write = None

    def check_device(self):
        pass

    def rd(self, offset):
        return self.reg[offset]

    def wr(self, offset, value):
        self.writes.append((offset, value))
        if offset == b.CTRL:
            # Hardware: EFP, SBFE and RESENSE_DISABLE return to their fused value 1.
            self.reg[b.EFP] = self.reg[b.SBFE] = self.reg[a.RESENSE_DISABLE] = 1
        else:
            self.reg[offset] = value
            if offset == b.WDATA_SECURE:
                self.reg[b.WDATA_PLM] = 0xffffffff
        if self.after_write:
            self.after_write(offset, value)


class ArmingTests(unittest.TestCase):
    def test_success_restores_sbfe_after_sense(self):
        dev = FakeIO()
        result = a.run(dev, lambda *args, **kwargs: None)
        self.assertEqual(dev.writes, list(a.WRITES))
        self.assertEqual(result['registers']['SBFE'], 0)
        self.assertFalse(result['fuses_burned'])

    def test_used_resense_stops_before_any_write(self):
        dev = FakeIO()
        dev.reg[a.RESENSE_DISABLE] = 1
        with self.assertRaises(ValueError):
            a.run(dev, lambda *args, **kwargs: None)
        self.assertEqual(dev.writes, [])

    def test_resense_lock_after_intent_stops_before_sense(self):
        dev = FakeIO()
        def journal(event, **data):
            if event == 'write-intent':
                dev.reg[a.RESENSE_DISABLE] = 1
        with self.assertRaises(ValueError):
            a.run(dev, journal)
        self.assertEqual(dev.writes, [])

    def test_success_records_resense_lock(self):
        dev = FakeIO()
        result = a.run(dev, lambda *args, **kwargs: None)
        self.assertEqual(result['registers']['RESENSE_DISABLE'], 1)

    def test_already_enabled_skips_sense(self):
        dev = FakeIO()
        dev.reg[b.EFP] = 1
        a.run(dev, lambda *args, **kwargs: None)
        self.assertEqual(dev.writes, list(a.WRITES[1:]))

    def test_initial_failures_issue_no_writes(self):
        for offset, value in ((b.CRC, 0), (b.DSOV, 1), (b.DEBUG, 2),
                              (b.EFP, 2), (b.CTRL, 0), (b.CTRL_PLM, 0),
                              (0x8200fc, 0), (0, 0xffffffff), (b.SBFE, 0xbadf510c)):
            with self.subTest(offset=offset):
                dev = FakeIO()
                dev.reg[offset] = value
                with self.assertRaises(ValueError):
                    a.run(dev, lambda *args, **kwargs: None)
                self.assertEqual(dev.writes, [])

    def test_resense_failure_stops_before_shadows(self):
        for offset, value in ((b.EFP, 0), (b.DSOV, 1), (b.CRC, 0), (b.DEBUG, 2)):
            with self.subTest(offset=offset):
                dev = FakeIO()
                dev.after_write = lambda *_: dev.reg.update({offset: value})
                with self.assertRaises(ValueError):
                    a.run(dev, lambda *args, **kwargs: None)
                self.assertEqual(dev.writes, [a.WRITES[0]])

    def test_timeout_no_retry_or_cleanup(self):
        dev = FakeIO()
        dev.after_write = lambda *_: dev.reg.update({b.CTRL: 0})
        with patch.object(b.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaises(TimeoutError):
                a.run(dev, lambda *args, **kwargs: None)
        self.assertEqual(dev.writes, [a.WRITES[0]])

    def test_shadow_readback_failure_stops(self):
        for blocked in (b.SW, b.SBFE, b.WDATA_SECURE):
            dev = FakeIO()
            def suppress(offset, value):
                if offset == blocked:
                    dev.reg[offset] = 1 - value
            dev.after_write = suppress
            with self.assertRaises(ValueError):
                a.run(dev, lambda *args, **kwargs: None)
            self.assertEqual(dev.writes[-1][0], blocked)

    def test_intent_failure_and_changed_guard_stop_before_write(self):
        for fail_log in (False, True):
            dev = FakeIO()
            def journal(event, **data):
                if event == 'write-intent':
                    if fail_log:
                        raise OSError('journal unavailable')
                    dev.reg[b.DSOV] = 1
            with self.assertRaises((ValueError, OSError)):
                a.run(dev, journal)
            self.assertEqual(dev.writes, [])

    def test_adapter_rejects_programming_and_unrelated_writes(self):
        bar = a.ArmBar.__new__(a.ArmBar)
        bar.check_device = lambda: None
        bar.mm = bytearray(b.MAP_SIZE)
        for offset, value in ((b.CTRL, 2), (b.CTRL, 1), (b.ADDR, 222),
                              (b.WDATA, 1), (b.EFP, 1), (b.SW, 0), (b.SBFE, 1)):
            with self.assertRaises(ValueError):
                bar.wr(offset, value)
        for offset, value in a.WRITES:
            bar.wr(offset, value)

    def test_default_and_invalid_cli_never_open_device(self):
        with patch.object(a, 'ArmBar') as device, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(a.main([]), 0)
            for argv in (['--bdf', '0000:01:00.0'], ['--arm'],
                         ['--arm', '--bdf', '../bad', '--journal', 'x']):
                with self.assertRaises(ValueError):
                    a.main(argv)
            device.assert_not_called()


if __name__ == '__main__':
    unittest.main()
