"""Safety regression tests for hardened ga100-ff-tools BAR0 and planner guards."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from common import bar0 as b0  # noqa: E402

sw_override = SourceFileLoader("mod_sw_override", str(REPO / "arm/sw_override.py")).load_module()
open_wdata = SourceFileLoader("mod_open_wdata", str(REPO / "arm/open_wdata_plm.py")).load_module()
arm_sense = SourceFileLoader("mod_arm_sense", str(REPO / "arm/arm_sense_ctrl.py")).load_module()
ff_burn = SourceFileLoader("mod_ff_burn", str(REPO / "burn/ff_burn.py")).load_module()
ff_dump = SourceFileLoader("mod_ff_dump", str(REPO / "planner/ff_dump.py")).load_module()
read_defects = SourceFileLoader("mod_read_defects", str(REPO / "planner/read_defects.py")).load_module()
ffcard = SourceFileLoader("mod_ffcard", str(REPO / "planner/ffcard.py")).load_module()


class FakeBar0(b0.Bar0):
    """In-memory GA100 fuse-controller simulator recording every MMIO read/write."""

    def __init__(self, read_only=False):
        self.regs = {
            b0.BOOT0: b0.GA100_BOOT0,
            b0.GFW_BOOT: 0x000000FF,
            b0.FUSECTRL: 0xE0040000,  # STATE_IDLE = 4 << 16
            b0.FUSEADDR: 0,
            b0.FUSERDATA: 0,
            b0.FUSEWDATA: 0,
            b0.EN_SW_OVERRIDE: 1,
            b0.DEBUGCTRL: 0,
            b0.CRC_STATUS: 0x55,
            b0.EFP: 1,
            b0.DFP: 0,
            b0.DSOV: 0,
            b0.FUSEWDATA_PLM: 0xFFFFFFFF,
            b0.FUSECTRL_PLM: 0xFFFFFFFF,
            b0.FUSEOPT_PLM: 0xFFFFFFFF,
            b0.WDATA_WR_SECURE: 0,
            b0.RESENSE_DISABLE: 0,
            b0.SBFE: 0,
        }
        for o in ff_dump.SHADOW.values():
            self.regs.setdefault(o, 0)
        for _, o in read_defects.REGS:
            self.regs.setdefault(o, 0)
        self.rows = {r: 0 for r in range(512)}
        for i, r in enumerate(range(8, 16)):
            self.rows[r] = 0xA0000000 + i
        self.reads = []
        self.writes = []
        self.stall_on_cmd = None
        self.poison_on_cmd = None
        self.on_sense_efp = 1
        self.on_sense_dsov = 0
        self.on_sense_sbfe = 0
        self.read_only = read_only
        self.bdf = "0000:01:00.0"
        self.fd = None
        self.mm = None
        self._owns_mm = False

    def rd(self, off):
        self.reads.append(off)
        return self.regs.get(off, 0)

    def wr(self, off, val):
        if self.read_only:
            raise PermissionError("read-only")
        self.writes.append((off, val))
        if off == b0.WDATA_WR_SECURE and val == 0 and self.regs[b0.DSOV] == 0 and self.regs[b0.EN_SW_OVERRIDE] == 1:
            self.regs[b0.WDATA_WR_SECURE] = 0
            self.regs[b0.FUSEWDATA_PLM] = 0xFFFFFFFF
            return
        if off == b0.EN_SW_OVERRIDE and self.regs[b0.DSOV] != 0:
            return
        if off == b0.FUSECTRL:
            cmd = val & 0xF
            if cmd == self.stall_on_cmd:
                self.regs[b0.FUSECTRL] = 0xE0010000 | cmd  # busy, never IDLE
                return
            if cmd == self.poison_on_cmd:
                self.regs[b0.FUSECTRL] = 0xBADF510E
                return
            if cmd == b0.CMD_READ:
                self.regs[b0.FUSERDATA] = self.rows[self.regs[b0.FUSEADDR]]
                self.regs[b0.FUSECTRL] = 0xE0040000
                return
            if cmd == b0.CMD_WRITE:
                self.rows[self.regs[b0.FUSEADDR]] |= self.regs[b0.FUSEWDATA]
                self.regs[b0.FUSECTRL] = 0xE0040000
                return
            if cmd == b0.CMD_SENSE_CTRL:
                self.regs[b0.EFP] = self.on_sense_efp
                self.regs[b0.DSOV] = self.on_sense_dsov
                self.regs[b0.SBFE] = self.on_sense_sbfe
                self.regs[b0.RESENSE_DISABLE] = 1
                self.regs[b0.FUSECTRL] = 0xE0040000
                return
            self.regs[b0.FUSECTRL] = 0xE0040000 | cmd
            return
        self.regs[off] = val

    def poll_idle(self, timeout_ms=1000, sleep_s=0.0):
        # Fast timeout in tests without sleeping.
        return super().poll_idle(timeout_ms=1, sleep_s=0.0)


class SafetyTests(unittest.TestCase):
    def test_no_struct_pack_into_in_live_bar0_scripts(self):
        import ast
        for rel in (
            "common/bar0.py",
            "arm/sw_override.py",
            "arm/open_wdata_plm.py",
            "arm/arm_sense_ctrl.py",
            "burn/ff_burn.py",
            "planner/ff_dump.py",
            "planner/read_defects.py",
            "planner/pcie_state.py",
        ):
            tree = ast.parse((REPO / rel).read_text(encoding="utf-8"), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "pack_into":
                    self.fail(f"struct.pack_into call/attr still present in {rel}")
                if isinstance(node, ast.Name) and node.id == "pack_into":
                    self.fail(f"pack_into reference still present in {rel}")

    def test_bar0_single_32bit_memoryview_read_write(self):
        buf = bytearray(b0.MAP_BYTES)
        bar = b0.Bar0(mm=buf, read_only=False)
        bar.wr(b0.FUSEWDATA, 0x12345678)
        self.assertEqual(bar.rd(b0.FUSEWDATA), 0x12345678)
        with self.assertRaises(ValueError):
            bar.wr(b0.FUSEWDATA + 1, 1)
        with self.assertRaises(ValueError):
            bar.wr(b0.FUSEWDATA, 1 << 32)
        ro = b0.Bar0(mm=buf, read_only=True)
        with self.assertRaises(PermissionError):
            ro.wr(b0.FUSEWDATA, 0)

    def test_sw_override_refuses_write_when_dsov_nonzero_and_on_poison(self):
        bar = FakeBar0()
        bar.regs[b0.DSOV] = 1
        bar.regs[b0.EN_SW_OVERRIDE] = 0
        out = sw_override.run_with_bar(bar, "0000:01:00.0", 1, read_only=False)
        self.assertFalse(out["works"])
        self.assertEqual(bar.writes, [])

        bar2 = FakeBar0()
        bar2.regs[b0.FUSECTRL] = 0xBAD01234
        with self.assertRaises(b0.Bar0Abort):
            sw_override.run_with_bar(bar2, "0000:01:00.0", 1, read_only=False)
        self.assertEqual(bar2.reads, [b0.FUSECTRL])
        self.assertEqual(bar2.writes, [])

    def test_open_wdata_plm_refuses_without_dsov0_and_en_sw(self):
        bar = FakeBar0()
        bar.regs[b0.EN_SW_OVERRIDE] = 0
        bar.regs[b0.WDATA_WR_SECURE] = 1
        bar.regs[b0.FUSEWDATA_PLM] = 0
        out = open_wdata.run_with_bar(bar, "0000:01:00.0", read_only=False)
        self.assertFalse(out["opened"])
        self.assertEqual(bar.writes, [])

    def test_arm_sense_stops_immediately_on_timeout_without_post_reads(self):
        bar = FakeBar0()
        bar.regs[b0.EFP] = 0
        bar.stall_on_cmd = b0.CMD_SENSE_CTRL
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(b0.Bar0Abort):
                arm_sense.execute(bar, confirm=True, input_fn=lambda _: "SENSE", post_sense_sleep=0)
        # Verify FUSEWDATA=0 was written before SENSE_CTRL
        self.assertIn((b0.FUSEWDATA, 0), bar.writes)
        # Verify NO register other than FUSECTRL was read after CMD_SENSE_CTRL was issued
        sense_idx = bar.writes.index((b0.FUSECTRL, b0.CMD_SENSE_CTRL))
        self.assertEqual(sense_idx, len(bar.writes) - 1)
        # All reads during/after poll must only be FUSECTRL (no 15-reg snap!)
        self.assertEqual(bar.reads[-1], b0.FUSECTRL)
        self.assertNotIn(b0.FUSEOPT_PLM, bar.reads[bar.reads.index(b0.FUSEWDATA):])

    def test_arm_sense_checks_remaining_guards_when_already_efp1(self):
        bar = FakeBar0()
        bar.regs[b0.EFP] = 1
        bar.regs[b0.DSOV] = 0
        bar.regs[b0.CRC_STATUS] = 0x77
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = arm_sense.execute(bar, confirm=False)
        self.assertEqual(rc, 1)
        self.assertEqual(bar.writes, [])

    def test_ff_burn_dry_run_never_issues_cmd_read_when_prereqs_fail(self):
        bar = FakeBar0()
        bar.regs[b0.CRC_STATUS] = 0x77
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ff_burn.execute(bar, 250, 0x000001C1, confirm=False)
        self.assertEqual(rc, 1)
        self.assertEqual(bar.writes, [], "CMD_READ must NOT be issued after failed prereqs")

    def test_ff_burn_rejects_bad_targets_and_happy_path_burns(self):
        with self.assertRaises(ValueError):
            ff_burn.validate_target(250, 0)
        with self.assertRaises(ValueError):
            ff_burn.validate_target(250, 0x000001E1)  # IFF bit 5 set
        with self.assertRaises(ValueError):
            ff_burn.validate_target(250, (0x416A << 16) | (37 << 6) | 2)  # forbidden DEVIDA
        with self.assertRaises(ValueError):
            ff_burn.validate_target(221, 0x000001C1)

        bar = FakeBar0()
        want_hash = b0.die_id_hash([bar.rows[r] for r in range(8, 16)])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ff_burn.execute(bar, 250, 0x000001C1, confirm=True,
                                 expected_die_id_hash=want_hash, input_fn=lambda _: "BURN")
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertEqual(bar.rows[250], 0x000001C1)

        # Wrong die-ID refuses without writing CMD_WRITE
        bar2 = FakeBar0()
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = ff_burn.execute(bar2, 250, 0x000001C1, confirm=True,
                                  expected_die_id_hash="deadbeefdeadbeef", input_fn=lambda _: "BURN")
        self.assertEqual(rc2, 1)
        self.assertEqual(bar2.rows[250], 0)

    def test_ff_dump_refuses_raw_read_when_crc_bad_or_gfw_not_ready(self):
        bar = FakeBar0()
        bar.regs[b0.CRC_STATUS] = 0x57
        with self.assertRaises(b0.Bar0Abort):
            ff_dump.capture_with_bar(bar, "0000:01:00.0")
        self.assertEqual(bar.writes, [])

        bar2 = FakeBar0()
        bar2.regs[b0.GFW_BOOT] = 0x00000001
        with self.assertRaises(b0.Bar0Abort):
            ff_dump.capture_with_bar(bar2, "0000:01:00.0")
        self.assertEqual(bar2.writes, [])

    def test_ff_dump_aborts_on_first_timeout_and_captures_all_rows(self):
        bar = FakeBar0()
        bar.stall_on_cmd = b0.CMD_READ
        with self.assertRaises(b0.Bar0Abort):
            ff_dump.capture_with_bar(bar, "0000:01:00.0", read_die_id=False)
        # Only attempted the very first row (222), not all 266 rows!
        addr_writes = [v for o, v in bar.writes if o == b0.FUSEADDR]
        self.assertEqual(addr_writes, [222])

        bar_ok = FakeBar0()
        bar_ok.rows[222] = 0x00000141
        rep = ff_dump.capture_with_bar(bar_ok, "0000:01:00.0", all_rows=True)
        self.assertEqual(len(rep["all_rows"]), 512)
        self.assertEqual(len(rep["die_id"]), 8)
        self.assertEqual(len(rep["die_id_hash"]), 16)

    def test_ffcard_refuses_missing_controller_idle_shadow_defects_and_die_id(self):
        from test_tools import DEFECTS, dump, stock_words

        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            stock = dump(stock_words(), die_id_hash="1111222233334444")
            (d / "stock.json").write_text(json.dumps(stock))
            (d / "defects.json").write_text(json.dumps({
                "registers": [{"name": n, "value": "0x%08X" % v} for n, v in DEFECTS.items()]
            }))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["derive", "--card", "c1", "--dump", str(d / "stock.json"),
                                  "--defects", str(d / "defects.json"), "--out-dir", str(d / "plans"),
                                  "--plans", "sm_hbm"])
            self.assertEqual(rc, 0, buf.getvalue())
            plan_path = d / "plans" / "c1_plan_sm_hbm.json"
            plan = json.loads(plan_path.read_text())
            self.assertEqual(plan["baseline"]["die_id_hash"], "1111222233334444")

            # Missing controller_idle must FAIL check
            win_no_idle = dump(stock_words(), die_id_hash="1111222233334444")
            del win_no_idle["controller_idle"]
            (d / "no_idle.json").write_text(json.dumps(win_no_idle))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["check", "--dump", str(d / "no_idle.json"), str(plan_path)])
            self.assertEqual(rc, 1)
            self.assertIn("controller_idle", buf.getvalue())

            # Wrong die_id_hash must FAIL check even when FF rows match
            win_wrong_die = dump(stock_words(), die_id_hash="9999888877776666")
            (d / "wrong_die.json").write_text(json.dumps(win_wrong_die))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["check", "--dump", str(d / "wrong_die.json"), str(plan_path)])
            self.assertEqual(rc, 1)
            self.assertIn("die_id_hash", buf.getvalue())

            # Final dump missing shadow dict must FAIL verify
            final_words = stock_words() + [int(r["encoded"], 16) for r in plan["records"]]
            fin_no_shadow = dump(final_words, include_shadow=False, die_id_hash="1111222233334444")
            (d / "fin_no_shadow.json").write_text(json.dumps(fin_no_shadow))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["verify", "--dump", str(d / "fin_no_shadow.json"), str(plan_path)])
            self.assertEqual(rc, 1)
            self.assertIn("missing required 'shadow'", buf.getvalue())

            # Empty defects file passed to verify must FAIL (not silently skip!)
            fin_ok = dump(final_words, include_shadow=True, die_id_hash="1111222233334444")
            (d / "fin_ok.json").write_text(json.dumps(fin_ok))
            (d / "empty_def.json").write_text(json.dumps({"registers": []}))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["verify", "--dump", str(d / "fin_ok.json"),
                                  "--defects", str(d / "empty_def.json"), str(plan_path)])
            self.assertEqual(rc, 1)
            self.assertIn("defects file lacks", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
