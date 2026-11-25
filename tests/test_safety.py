"""Safety regression tests for hardened ga100-ff-tools BAR0, planner, burn, and bench guards."""
import ast
import contextlib
import hashlib
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
sm_stress = SourceFileLoader("mod_sm_stress", str(REPO / "bench/sm_stress.py")).load_module()


class FakeBar0(b0.Bar0):
    """In-memory GA100 fuse-controller simulator recording every MMIO read/write."""

    def __init__(self, read_only=False):
        self.regs = {
            b0.BOOT0: b0.GA100_BOOT0,
            b0.GFW_BOOT: 0x000000FF,
            b0.FUSECTRL: 0xE0040000,  # STATE_IDLE = 4 << 16, CMD_IDLE = 0
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
        self.rows[222] = 0xFFFF0141
        self.rows[223] = 0xFFFF0181
        self.reads = []
        self.writes = []
        self.stall_on_cmd = None
        self.poison_on_cmd = None
        self.addr_latch_broken = False
        self.wdata_latch_broken = False
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
        if off == b0.FUSEADDR and self.addr_latch_broken:
            self.regs[b0.FUSEADDR] = 0
            return
        if off == b0.FUSEWDATA and self.wdata_latch_broken:
            self.regs[b0.FUSEWDATA] = 0
            return
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
        return super().poll_idle(timeout_ms=1, sleep_s=0.0)


def make_plan_for_bar(bar, records, prior_records=None, mode="sm_hbm"):
    die_vals = [bar.rows[r] for r in range(8, 16)]
    die_hex = ["0x%08X" % v for v in die_vals]
    dh = b0.die_id_hash(die_vals)
    last_row = 223
    fp_str = ",".join("0x%08X" % bar.rows[r] for r in range(222, last_row + 1))
    fp = hashlib.sha256(fp_str.encode("ascii")).hexdigest()[:16]
    return {
        "schema_version": 2,
        "card": "c01",
        "mode": mode,
        "baseline": {
            "last_row": last_row,
            "fingerprint": fp,
            "die_id": die_hex,
            "die_id_hash": dh,
        },
        "prior_records": list(prior_records or []),
        "records": records,
    }


class SafetyTests(unittest.TestCase):
    def test_no_struct_pack_into_in_live_bar0_scripts(self):
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

    def test_bar0_alignment_bounds_and_boot0_check(self):
        buf = bytearray(b0.MAP_BYTES)
        bar = b0.Bar0(mm=buf, read_only=False)
        bar.wr(b0.FUSEWDATA, 0x12345678)
        self.assertEqual(bar.rd(b0.FUSEWDATA), 0x12345678)
        for bad_off in (-4, 1, b0.MAP_BYTES, b0.MAP_BYTES - 2):
            with self.assertRaises(ValueError):
                bar.rd(bad_off)
            with self.assertRaises(ValueError):
                bar.wr(bad_off, 1)
        with self.assertRaises(ValueError):
            bar.wr(b0.FUSEWDATA, 1 << 32)
        ro = b0.Bar0(mm=buf, read_only=True)
        with self.assertRaises(PermissionError):
            ro.wr(b0.FUSEWDATA, 0)

        fbar = FakeBar0()
        fbar.regs[b0.BOOT0] = 0x12345678
        with self.assertRaises(b0.Bar0Abort):
            fbar.check_health_first()
        self.assertEqual(fbar.reads, [b0.FUSECTRL, b0.BOOT0])

        # FUSEADDR latch failure aborts before CMD_READ
        fbar2 = FakeBar0()
        fbar2.addr_latch_broken = True
        with self.assertRaises(b0.Bar0Abort):
            fbar2.read_row(222)
        self.assertNotIn((b0.FUSECTRL, b0.CMD_READ), fbar2.writes)

    def test_sw_override_and_open_wdata_refuse_bad_crc_dsov_poison(self):
        bar = FakeBar0()
        bar.regs[b0.CRC_STATUS] = 0x77
        out = sw_override.run_with_bar(bar, "0000:01:00.0", 1, read_only=False)
        self.assertFalse(out["works"])
        self.assertEqual(bar.writes, [])

        bar_ow = FakeBar0()
        bar_ow.regs[b0.CRC_STATUS] = 0x77
        out2 = open_wdata.run_with_bar(bar_ow, "0000:01:00.0", read_only=False)
        self.assertFalse(out2["opened"])
        self.assertEqual(bar_ow.writes, [])

        bar2 = FakeBar0()
        bar2.regs[b0.FUSECTRL] = 0xBAD01234
        with self.assertRaises(b0.Bar0Abort):
            sw_override.run_with_bar(bar2, "0000:01:00.0", 1, read_only=False)
        self.assertEqual(bar2.reads, [b0.FUSECTRL])
        self.assertEqual(bar2.writes, [])

    def test_arm_sense_fail_fast_raw_wdata_recheck_and_efp_guard(self):
        # GFW stall inside snap() stops after 2 reads (FUSECTRL + GFW_BOOT), ZERO extra reads!
        bar_gfw = FakeBar0()
        bar_gfw.regs[b0.GFW_BOOT] = 0x00000001
        with self.assertRaises(b0.Bar0Abort):
            arm_sense.snap(bar_gfw)
        self.assertEqual(bar_gfw.reads, [b0.FUSECTRL, b0.GFW_BOOT])

        # Raw FUSEWDATA containing 0xBAD00001 does NOT cause false PRI poison abort
        bar_raw = FakeBar0()
        bar_raw.regs[b0.EFP] = 0
        bar_raw.regs[b0.FUSEWDATA] = 0xBAD00001
        s = arm_sense.snap(bar_raw)
        self.assertEqual(s["FUSEWDATA"], 0xBAD00001)

        # Unexpected EFP=2 is rejected, never treated as normal window
        bar_efp = FakeBar0()
        bar_efp.regs[b0.EFP] = 2
        with contextlib.redirect_stdout(io.StringIO()):
            rc = arm_sense.execute(bar_efp, confirm=False)
        self.assertEqual(rc, 1)
        self.assertEqual(bar_efp.writes, [])

        # Window state changing during human confirmation aborts before any write
        bar_chg = FakeBar0()
        bar_chg.regs[b0.EFP] = 0

        def mutate_then_confirm(_prompt):
            bar_chg.regs[b0.DSOV] = 1
            return "SENSE"

        with contextlib.redirect_stdout(io.StringIO()):
            rc = arm_sense.execute(bar_chg, confirm=True, input_fn=mutate_then_confirm, post_sense_sleep=0)
        self.assertEqual(rc, 1)
        self.assertEqual(bar_chg.writes, [])

        # Timeout on SENSE_CTRL leaves ZERO post-timeout reads
        bar = FakeBar0()
        bar.regs[b0.EFP] = 0
        bar.stall_on_cmd = b0.CMD_SENSE_CTRL
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(b0.Bar0Abort):
                arm_sense.execute(bar, confirm=True, input_fn=lambda _: "SENSE", post_sense_sleep=0)
        self.assertIn((b0.FUSEWDATA, 0), bar.writes)
        last_wdata = len(bar.reads) - 1 - bar.reads[::-1].index(b0.FUSEWDATA)
        self.assertEqual(set(bar.reads[last_wdata + 1:]), {b0.FUSECTRL})

    def test_ff_dump_zero_wasted_reads_on_crc_gfw_or_rwl_fault(self):
        # Bad CRC stops after FUSECTRL, BOOT0, GFW, CRC_STATUS (4 reads total; 0 shadow/defect/row reads)
        bar = FakeBar0()
        bar.regs[b0.CRC_STATUS] = 0x57
        with self.assertRaises(b0.Bar0Abort):
            ff_dump.capture_with_bar(bar, "0000:01:00.0")
        self.assertEqual(bar.reads, [b0.FUSECTRL, b0.BOOT0, b0.GFW_BOOT, b0.CRC_STATUS])
        self.assertEqual(bar.writes, [])

        # Shadow-only on GFW stall stops after 3 reads (0 shadow/defect reads!)
        bar_sh = FakeBar0()
        bar_sh.regs[b0.GFW_BOOT] = 0x00000001
        with self.assertRaises(b0.Bar0Abort):
            ff_dump.capture_with_bar(bar_sh, "0000:01:00.0", shadow_only=True)
        self.assertEqual(bar_sh.reads, [b0.FUSECTRL, b0.BOOT0, b0.GFW_BOOT])

        # DEBUGCTRL.RWL=1 stops after 5 reads (0 shadow/defect/row reads!)
        bar_rwl = FakeBar0()
        bar_rwl.regs[b0.DEBUGCTRL] = b0.RWL_BIT
        with self.assertRaises(b0.Bar0Abort):
            ff_dump.capture_with_bar(bar_rwl, "0000:01:00.0")
        self.assertEqual(bar_rwl.reads, [b0.FUSECTRL, b0.BOOT0, b0.GFW_BOOT, b0.CRC_STATUS, b0.DEBUGCTRL])

        # Healthy capture embeds defects + die_id + all_rows in one session
        bar_ok = FakeBar0()
        rep = ff_dump.capture_with_bar(bar_ok, "0000:01:00.0", all_rows=True)
        self.assertIn("defects", rep)
        self.assertIn("OPT_PES_DISABLE", rep["defects"])
        self.assertIn("OPT_ROP_L2_DISABLE", rep["defects"])
        self.assertEqual(len(rep["all_rows"]), 512)
        self.assertEqual(len(rep["die_id"]), 8)

    def test_ff_burn_plan_prefix_negative_index_devidb_bit0_and_journal_lock(self):
        bar = FakeBar0()
        rec0 = {"row": 224, "chain": 1, "block": 7, "old_data": "0xFFFF", "new_data": "0x0000", "encoded": "0x000001C1"}
        rec1 = {"row": 225, "chain": 1, "block": 8, "old_data": "0xFFFF", "new_data": "0x0000", "encoded": "0x00000201"}
        plan = make_plan_for_bar(bar, [rec0, rec1])

        # Negative index refused
        with self.assertRaises(ValueError):
            ff_burn.validate_plan_and_index(plan, -1)

        # Forbidden DEVIDB MSB bit 0 on block (2, 39) refused
        bad_rec = {"row": 224, "chain": 2, "block": 39, "old_data": "0x0782", "new_data": "0x0783",
                   "encoded": "0x%08X" % ((0x0783 << 16) | (39 << 6) | 2)}
        with self.assertRaises(ValueError):
            ff_burn.validate_target(224, int(bad_rec["encoded"], 16), rec=bad_rec)

        with tempfile.TemporaryDirectory() as td:
            jpath = str(Path(td) / "burn.journal.json")

            # Skipping index 0 when trying index 1 MUST FAIL!
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ff_burn.execute_plan(bar, plan, 1, confirm=False, journal_path=jpath)
            self.assertEqual(rc, 1)
            self.assertIn("do NOT skip", buf.getvalue())

            # Dry-run prints old_data -> new_data preview
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ff_burn.execute_plan(bar, plan, 0, confirm=False, journal_path=jpath)
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertIn("0xFFFF -> 0x0000", buf.getvalue())

            # Confirmed burn of index 0 succeeds and records VERIFIED_OK
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ff_burn.execute_plan(bar, plan, 0, confirm=True, input_fn=lambda _: "BURN",
                                          journal_path=jpath)
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertEqual(bar.rows[224], 0x000001C1)
            jdata = json.loads(Path(jpath).read_text())
            self.assertFalse(jdata["aborted"])
            self.assertEqual(jdata["entries"][0]["status"], "VERIFIED_OK")

            # Timeout on index 1 marks journal aborted=true and blocks ANY subsequent burn!
            bar.stall_on_cmd = b0.CMD_WRITE
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(b0.Bar0Abort):
                    ff_burn.execute_plan(bar, plan, 1, confirm=True, input_fn=lambda _: "BURN",
                                         journal_path=jpath)
            jdata = json.loads(Path(jpath).read_text())
            self.assertTrue(jdata["aborted"])
            self.assertEqual(jdata["entries"][-1]["status"], "ABORTED_IO")

            # Even after clearing stall, aborted journal blocks retry!
            bar.stall_on_cmd = None
            bar.regs[b0.FUSECTRL] = 0xE0040000
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                rc2 = ff_burn.execute_plan(bar, plan, 1, confirm=True, input_fn=lambda _: "BURN",
                                           journal_path=jpath)
            self.assertEqual(rc2, 1)
            self.assertIn("aborted=true", buf2.getvalue())

    def test_ffcard_stage_isolation_cross_card_defects_missing_shadows_and_prefix(self):
        from test_tools import DEFECTS, dump, stock_words

        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            stock_b = dump(stock_words(), dsov=1, die_id_hash="bbbbbbbbbbbbbbbb")
            (d / "stock_b.json").write_text(json.dumps(stock_b))

            # Card A defects (or unbound defects lacking die_id_hash) + Card B dump MUST BE REFUSED!
            defects_unbound = {"bdf": "0000:01:00.0",
                               "registers": [{"name": n, "value": "0x%08X" % v} for n, v in DEFECTS.items()]}
            (d / "def_unbound.json").write_text(json.dumps(defects_unbound))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["derive", "--card", "b", "--dump", str(d / "stock_b.json"),
                                  "--defects", str(d / "def_unbound.json"), "--out-dir", str(d / "p_bad")])
            self.assertEqual(rc, 1)
            self.assertIn("die_id_hash", buf.getvalue())

            defects_a = {"die_id_hash": "aaaaaaaaaaaaaaaa",
                         "registers": [{"name": n, "value": "0x%08X" % v} for n, v in DEFECTS.items()]}
            (d / "def_a.json").write_text(json.dumps(defects_a))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["derive", "--card", "b", "--dump", str(d / "stock_b.json"),
                                  "--defects", str(d / "def_a.json"), "--out-dir", str(d / "p_bad")])
            self.assertEqual(rc, 1)
            self.assertIn("wrong-card defects refused", buf.getvalue())

            # Derive noop + sm_hbm without requiring NVLink defect mask
            def_no_nv = {k: v for k, v in DEFECTS.items() if k != "OPT_NVLINK_DEFECTIVE"}
            stock_no_nv = dump(stock_words(), dsov=1, die_id_hash="bbbbbbbbbbbbbbbb", defects_override=def_no_nv)
            (d / "stock_no_nv.json").write_text(json.dumps(stock_no_nv))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["derive", "--card", "b", "--dump", str(d / "stock_no_nv.json"),
                                  "--out-dir", str(d / "plans"), "--plans", "noop", "sm_hbm"])
            self.assertEqual(rc, 0, buf.getvalue())
            p_noop = d / "plans" / "b_plan_0_noop.json"
            p_sm = d / "plans" / "b_plan_sm_hbm.json"

            # Cold dump (DSOV=1) MUST BE REFUSED by check!
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["check", "--dump", str(d / "stock_no_nv.json"), str(p_noop), str(p_sm)])
            self.assertEqual(rc, 1)
            self.assertIn("cold dump refused", buf.getvalue())

            # Passing only sm_hbm without preceding 0_noop MUST BE REFUSED!
            win_dump = dump(stock_words(), dsov=0, die_id_hash="bbbbbbbbbbbbbbbb")
            (d / "win.json").write_text(json.dumps(win_dump))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["check", "--dump", str(d / "win.json"), str(p_sm)])
            self.assertEqual(rc, 1)
            self.assertIn("missing preceding plan record", buf.getvalue())

            # GFW=0xFFFFFFFF or 0xBAD000FF MUST BE REFUSED!
            for bad_gfw in ("0xFFFFFFFF", "0xBAD000FF"):
                bad_win = dump(stock_words(), dsov=0, die_id_hash="bbbbbbbbbbbbbbbb")
                bad_win["gfw"] = bad_gfw
                (d / "bad_gfw.json").write_text(json.dumps(bad_win))
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    rc = ffcard.main(["check", "--dump", str(d / "bad_gfw.json"), str(p_noop), str(p_sm)])
                self.assertEqual(rc, 1)
                self.assertIn("not ready / dead / poisoned", buf.getvalue())

            # Missing explicit row cannot be backfilled via blank_rows!
            partial_win = dump(stock_words(), dsov=0, die_id_hash="bbbbbbbbbbbbbbbb")
            partial_win["rows"].pop()
            partial_win["blank_rows"] = [487]
            (d / "partial.json").write_text(json.dumps(partial_win))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["check", "--dump", str(d / "partial.json"), str(p_noop), str(p_sm)])
            self.assertEqual(rc, 1)
            self.assertIn("missing explicit row", buf.getvalue())

            # Final verify: in-window DSOV=0 dump MUST FAIL verify!
            recs = json.loads(p_noop.read_text())["records"] + json.loads(p_sm.read_text())["records"]
            final_words = stock_words() + [int(r["encoded"], 16) for r in recs]
            win_final = dump(final_words, dsov=0, die_id_hash="bbbbbbbbbbbbbbbb")
            (d / "win_final.json").write_text(json.dumps(win_final))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["verify", "--dump", str(d / "win_final.json"), str(p_noop), str(p_sm)])
            self.assertEqual(rc, 1)
            self.assertIn("DSOV=1", buf.getvalue())

            # Final verify missing OPT_PES_DISABLE / OPT_ROP_L2_DISABLE shadows MUST FAIL verify!
            cold_missing_pes = dump(final_words, dsov=1, die_id_hash="bbbbbbbbbbbbbbbb")
            del cold_missing_pes["defects"]["OPT_PES_DISABLE"]
            (d / "cold_no_pes.json").write_text(json.dumps(cold_missing_pes))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["verify", "--dump", str(d / "cold_no_pes.json"), str(p_noop), str(p_sm)])
            self.assertEqual(rc, 1)
            self.assertIn("OPT_PES_DISABLE", buf.getvalue())

            # Final verify with tampered truncated expect_fields MUST FAIL verify!
            cold_ok = dump(final_words, dsov=1, die_id_hash="bbbbbbbbbbbbbbbb")
            (d / "cold_ok.json").write_text(json.dumps(cold_ok))
            tampered = json.loads(p_sm.read_text())
            del tampered["expect_fields"]["OPT_GPC_DISABLE"]
            p_sm_bad = d / "plans" / "b_plan_sm_tampered.json"
            p_sm_bad.write_text(json.dumps(tampered))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["verify", "--dump", str(d / "cold_ok.json"), str(p_noop), str(p_sm_bad)])
            self.assertEqual(rc, 1)
            self.assertIn("canonical", buf.getvalue())

            # Clean cold-boot verify PASSES!
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = ffcard.main(["verify", "--dump", str(d / "cold_ok.json"), str(p_noop), str(p_sm)])
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertIn("VERIFY PASS", buf.getvalue())

    def test_sm_stress_coverage_evaluator(self):
        present = list(range(108))
        self.assertEqual(len(sm_stress.select_ids(present, "all")), 108)
        self.assertEqual(sm_stress.evaluate_coverage(present, set(present), expected_sms=108, reported_nsm=108), [])
        probs = sm_stress.evaluate_coverage(present, set(present[:-1]), expected_sms=108, reported_nsm=108)
        self.assertTrue(any("missed" in p for p in probs))
        probs2 = sm_stress.evaluate_coverage(present, set(present), expected_sms=110, reported_nsm=108)
        self.assertTrue(any("driver reported 108 SMs" in p for p in probs2))


if __name__ == "__main__":
    unittest.main()
