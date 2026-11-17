"""Public burner injected-I/O tests. Never opens a PCI device."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch

import test_conversion as fixtures
from test_tools import load

b = load('public_burner', Path(__file__).resolve().parents[1]/'ffburn.py3')
real_confirm_programming = b.confirm_programming


class FakeIO:
    def __init__(self, rows):
        self.rows = rows[:]
        self.reg = {b.IFF_RECORD:(507<<16)|488,b.CTRL:0xe0040000,b.ADDR:7,b.DEBUG:0,b.CRC:0x55,b.DSOV:0,
                    b.EFP:1,b.SBFE:0,b.SW:1,b.WDATA_SECURE:0,
                    b.WDATA_PLM:0xffffffff,b.CTRL_PLM:0xffffffff,0:0x170000a1}
        self.writes = []
        self.programs = []
        self.suppress = self.timeout = self.driver = False
        self.after_stage = None
        self.read_transform = None
    def check_device(self):
        if self.driver:
            raise ValueError('Driver bound')
    def rd(self, offset):
        if offset == b.RDATA:
            value = self.rows[self.reg[b.ADDR]]
            return self.read_transform(self.reg[b.ADDR], value) if self.read_transform else value
        return self.reg.get(offset, 0)
    def wr(self, offset, value):
        self.check_device()
        self.writes.append((offset,value))
        if offset == b.CTRL:
            self.reg[offset] = 0xe0040000
            if value == b.CMD_WRITE:
                self.programs.append((self.reg[b.ADDR],self.reg[b.WDATA]))
                if self.timeout:
                    self.reg[offset] = 0
                elif not self.suppress:
                    self.rows[self.reg[b.ADDR]] |= self.reg[b.WDATA]
        else:
            self.reg[offset] = value
            if offset == b.WDATA and self.after_stage:
                self.after_stage()


class BurnerTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.ConversionTests('test_all_features_allocate_unique_rows_and_replay')
        fixture.setUp()
        self.addCleanup(fixture.temp.cleanup)
        self.baseline = fixture.path
        self.plan = fixture.plan(list(fixtures.p.GROUPS))
        self.plan_path = self.baseline.with_name('plan.json')
        self.plan_path.write_text(json.dumps(self.plan))
        self.context = b.prepare(self.baseline,self.plan_path)
        self.io = FakeIO(self.context['rows'])
        self.events = []
        confirmer = patch.object(b, 'confirm_programming')
        self.confirm = confirmer.start()
        self.addCleanup(confirmer.stop)
    def journal(self,event,**data):
        self.events.append((event,data))
    def run_burn(self):
        return b.run(self.context,self.io,self.journal,execute=True)
    def test_fuse_command_constants_match_the_protocol(self):
        self.assertEqual((b.CMD_IDLE, b.CMD_READ, b.CMD_WRITE, b.CMD_SENSE), (0, 1, 2, 3))
        self.assertEqual(b.CMD_MASK, 3)

    def test_full_conversion_plan_programs_once_and_verifies(self):
        result = self.run_burn()
        self.assertEqual(len(self.io.programs),len(self.plan['records']))
        self.assertEqual(len(set(row for row,_ in self.io.programs)),len(self.io.programs))
        self.assertTrue(result['full_array_verified'])
        self.assertFalse(result['cold_boot_verified'])
        self.assertFalse(result['working_features_verified'])
        self.assertEqual(self.io.reg[b.ADDR],7)
        for record in self.plan['records']:
            self.assertEqual(self.io.rows[record['row']],record['word'])
        intents=[event for event,_ in self.events if event=='program-intent']
        self.assertEqual(len(intents),len(self.plan['records']))
    def test_preflight_issues_reads_but_no_program_data_or_commands(self):
        result=b.run(self.context,self.io,self.journal)
        self.assertEqual(result['mode'],'preflight')
        self.assertFalse(self.io.programs)
        self.assertFalse(any(off==b.WDATA or (off==b.CTRL and value==b.CMD_WRITE) for off,value in self.io.writes))
        self.assertEqual(self.io.reg[b.ADDR],7)
    def test_offline_default_does_not_open_journal_or_hardware(self):
        with patch.object(b,'LinuxBar',side_effect=AssertionError('hardware')), patch.object(b,'Journal',side_effect=AssertionError('journal')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(b.main(['--baseline',str(self.baseline),'--plan',str(self.plan_path)]),0)
    def test_wrong_plan_id_or_bdf_rejected_before_hardware(self):
        for extra in (['--execute-plan','wrong','--bdf','0000:01:00.0','--journal','unused'],['--preflight','--bdf','0000:02:00.0','--journal','unused']):
            with self.subTest(extra=extra),patch.object(b,'LinuxBar',side_effect=AssertionError('hardware')):
                with self.assertRaises(ValueError):
                    b.main(['--baseline',str(self.baseline),'--plan',str(self.plan_path),*extra])
    def test_tampered_record_rejected(self):
        self.plan['records'][0]['word']^=1
        self.plan_path.write_text(json.dumps(self.plan))
        with self.assertRaisesRegex(ValueError,'regeneration'):
            b.prepare(self.baseline,self.plan_path)
    def test_wrong_physical_card_prevents_every_program(self):
        self.io.rows[100]^=1
        with self.assertRaisesRegex(ValueError,'baseline'):
            self.run_burn()
        self.assertFalse(self.io.programs)
    def test_all_prerequisites_fail_before_row_commands(self):
        for offset,value in ((b.DEBUG,2),(b.DEBUG,1),(b.DEBUG,0xffffffff),(b.CRC,0),(b.DSOV,1),(b.EFP,0),(b.SBFE,1),(b.SW,0),(b.WDATA_SECURE,1),(b.WDATA_PLM,0xffffff8f),(b.CTRL_PLM,0),(b.CTRL,0),(0,0)):
            with self.subTest(offset=offset,value=value):
                fake=FakeIO(self.context['rows']);fake.reg[offset]=value
                with self.assertRaises(ValueError):
                    b.run(self.context,fake,self.journal,execute=True)
                self.assertEqual(fake.writes,[])
    def test_guard_loss_after_staging_never_issues_program(self):
        self.io.after_stage=lambda:self.io.reg.__setitem__(b.DSOV,1)
        with self.assertRaisesRegex(ValueError,'DSOV'):
            self.run_burn()
        self.assertFalse(self.io.programs)
    def test_stale_state_after_durable_intent_rejected(self):
        def journal(event,**data):
            if event=='program-intent':self.io.reg[b.DEBUG]=2
        with self.assertRaisesRegex(ValueError,'DEBUGCTRL'):
            b.run(self.context,self.io,journal,execute=True)
        self.assertFalse(self.io.programs)
    def test_row_becomes_occupied_after_scan_rejected(self):
        def journal(event,**data):
            if event=='program-intent':self.io.rows[data['row']]=1
        with self.assertRaisesRegex(ValueError,'no longer blank'):
            b.run(self.context,self.io,journal,execute=True)
        self.assertFalse(self.io.programs)
    def test_failed_intent_journal_never_programs(self):
        def journal(event,**data):
            if event=='program-intent':raise OSError('disk failure')
        with self.assertRaisesRegex(OSError,'disk failure'):
            b.run(self.context,self.io,journal,execute=True)
        self.assertFalse(self.io.programs)
    def test_readback_failure_stops_after_one_attempt(self):
        self.io.suppress=True
        with self.assertRaisesRegex(ValueError,'readback mismatch'):
            self.run_burn()
        self.assertEqual(len(self.io.programs),1)
        self.assertEqual(self.events[-1][0],'session-failed')
        self.assertEqual(self.io.writes[-1],(b.CTRL,b.CMD_READ))  # No cleanup MMIO after failure.
    def test_program_timeout_never_retries_or_issues_cleanup_read(self):
        self.io.timeout=True
        ticks=iter(range(100000))
        with patch.object(b.time,'monotonic',side_effect=lambda:next(ticks)),patch.object(b.time,'sleep'):
            # Bypass only the long full-array scan, retaining real per-record/timeout logic.
            with patch.object(b.Controller,'read_all',return_value=self.context['rows']):
                with self.assertRaisesRegex(TimeoutError,'timed out'):
                    self.run_burn()
        self.assertEqual(len(self.io.programs),1)
        self.assertEqual(self.io.writes[-1],(b.CTRL,b.CMD_WRITE))
    def test_pri_raw_data_rejected_but_physical_all_ones_accepted(self):
        self.io.rows[0]=0xffffffff
        self.context['rows'][0]=0xffffffff
        b.run(self.context,self.io,self.journal)
        self.io.read_transform=lambda row,value:0xbadf510c if row==0 else value
        with self.assertRaisesRegex(ValueError,'PRI'):
            self.run_burn()
        self.assertFalse(self.io.programs)
    def test_partial_success_cannot_resume_original_plan(self):
        calls=[0]
        def journal(event,**data):
            if event=='program-intent':
                calls[0]+=1
                if calls[0]==2:raise OSError('stop')
        with self.assertRaises(OSError):
            b.run(self.context,self.io,journal,execute=True)
        self.assertEqual(len(self.io.programs),1)
        with self.assertRaisesRegex(ValueError,'baseline'):
            self.run_burn()
        self.assertEqual(len(self.io.programs),1)
    def test_adapter_rejects_override_reset_gpio_and_sense_writes(self):
        adapter=b.LinuxBar.__new__(b.LinuxBar)
        adapter.mm=bytearray(b.MAP_SIZE)
        adapter.allow_program=True
        adapter.check_device=lambda:None
        for offset,value in ((b.SW,1),(b.SBFE,0),(b.WDATA_SECURE,0),(b.DEBUG,0),(0xd604,1),(b.CTRL,b.CMD_SENSE),(b.ADDR,512),(b.WDATA,-1),(b.CTRL,True)):
            with self.subTest(offset=offset,value=value),self.assertRaises(ValueError):
                adapter.wr(offset,value)
    def test_preflight_adapter_cannot_write_program_ports(self):
        adapter=b.LinuxBar.__new__(b.LinuxBar)
        adapter.allow_program=False
        adapter.mm=bytearray(b.MAP_SIZE)
        adapter.check_device=lambda:None
        for offset,value in ((b.WDATA,1),(b.CTRL,b.CMD_WRITE)):
            with self.assertRaisesRegex(ValueError,'Preflight'):
                adapter.wr(offset,value)
        adapter.wr(b.ADDR,222)
        adapter.wr(b.CTRL,b.CMD_READ)

    def test_journal_is_exclusive_and_durable(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'attempt.jsonl'
            journal=b.Journal(path)
            journal('test',value=1)
            journal.close()
            self.assertEqual(json.loads(path.read_text())['event'],'test')
            with self.assertRaises(FileExistsError):b.Journal(path)
    def test_live_device_checks_identity_driver_and_memory_decode(self):
        with tempfile.TemporaryDirectory() as temp:
            dev=Path(temp)
            config=bytearray(64)
            struct.pack_into('<HHH',config,0,0x10de,0x20c2,2)
            (dev/'config').write_bytes(config)
            adapter=b.LinuxBar.__new__(b.LinuxBar);adapter.dev=dev
            adapter.check_device()
            (dev/'driver').mkdir()
            with self.assertRaisesRegex(ValueError,'bound driver'):adapter.check_device()
            (dev/'driver').rmdir()
            for offset,value in ((2,0x20b5),(0,0xffff),(4,0)):
                changed=bytearray(config)
                struct.pack_into('<H',changed,offset,value)
                (dev/'config').write_bytes(changed)
                with self.assertRaises(ValueError):adapter.check_device()

    def test_journal_failure_after_landed_write_stops_following_records(self):
        def journal(event,**data):
            if event=='program-readback':raise OSError('journal lost')
        with self.assertRaisesRegex(OSError,'journal lost'):
            b.run(self.context,self.io,journal,execute=True)
        self.assertEqual(len(self.io.programs),1)
        self.assertEqual(self.io.rows[self.plan['records'][0]['row']],self.plan['records'][0]['word'])

    def test_outside_row_change_detected_by_final_verification(self):
        count=[0]
        def journal(event,**data):
            if event=='program-readback':
                count[0]+=1
                if count[0]==len(self.plan['records']):self.io.rows[100]^=1
        with self.assertRaisesRegex(ValueError,'full-array'):
            b.run(self.context,self.io,journal,execute=True)
        self.assertEqual(len(self.io.programs),len(self.plan['records']))

    def test_three_exact_confirmations(self):
        answers=[self.plan['bdf'],self.plan['plan_id'],'BURN %d ROWS' % len(self.plan['records'])]
        with patch.object(b.sys.stdin,'isatty',return_value=True), patch('builtins.input',side_effect=answers) as prompt, contextlib.redirect_stdout(io.StringIO()):
            real_confirm_programming(self.context)
        self.assertEqual(prompt.call_count,3)

    def test_each_wrong_confirmation_stops_immediately(self):
        valid=[self.plan['bdf'],self.plan['plan_id'],'BURN %d ROWS' % len(self.plan['records'])]
        for stage in range(3):
            answers=valid[:stage]+['wrong']
            with self.subTest(stage=stage), patch.object(b.sys.stdin,'isatty',return_value=True), patch('builtins.input',side_effect=answers) as prompt, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError,'did not match'):
                    real_confirm_programming(self.context)
            self.assertEqual(prompt.call_count,stage+1)

    def test_confirmation_eof_and_noninteractive_input_rejected(self):
        with patch.object(b.sys.stdin,'isatty',return_value=False), patch('builtins.input') as prompt:
            with self.assertRaisesRegex(ValueError,'interactive terminal'):
                real_confirm_programming(self.context)
            prompt.assert_not_called()
        with patch.object(b.sys.stdin,'isatty',return_value=True), patch('builtins.input',side_effect=EOFError), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError,'input ended'):
                real_confirm_programming(self.context)

    def test_interrupted_confirmation_never_programs(self):
        self.confirm.side_effect=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.run_burn()
        self.assertEqual(self.io.writes,[])
        self.assertFalse(self.io.programs)

    def test_declined_confirmation_issues_no_mmio(self):
        self.confirm.side_effect=ValueError('Confirmation did not match')
        with self.assertRaisesRegex(ValueError,'Confirmation'):
            self.run_burn()
        self.assertEqual(self.io.writes,[])
        self.assertFalse(self.io.programs)

    def test_guards_and_baseline_are_checked_after_confirmation(self):
        self.confirm.side_effect=lambda ctx:self.io.reg.__setitem__(b.DSOV,1)
        with self.assertRaisesRegex(ValueError,'DSOV'):
            self.run_burn()
        self.assertEqual(self.io.writes,[])
        self.confirm.side_effect=lambda ctx:self.io.rows.__setitem__(100,self.io.rows[100]^1)
        self.io.reg[b.DSOV]=0
        with self.assertRaisesRegex(ValueError,'baseline'):
            self.run_burn()
        self.assertFalse(self.io.programs)

    def test_preflight_never_asks_for_confirmation(self):
        b.run(self.context,self.io,self.journal,execute=False)
        self.confirm.assert_not_called()

    def test_live_iff_boundary_change_stops_before_any_row_command(self):
        self.io.reg[b.IFF_RECORD]=(507<<16)|331
        with self.assertRaisesRegex(ValueError,'Live IFF_RECORD'):
            self.run_burn()
        self.assertEqual(self.io.writes,[])

    def test_iff_boundary_change_after_staging_stops_program_command(self):
        self.io.after_stage=lambda:self.io.reg.__setitem__(b.IFF_RECORD,(507<<16)|331)
        with self.assertRaisesRegex(ValueError,'Live IFF_RECORD'):
            self.run_burn()
        self.assertFalse(self.io.programs)

    def test_existing_live_journal_blocks_device_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'attempt.jsonl';path.write_text('existing')
            with patch.object(b.sys,'platform','linux'),patch.object(b,'LinuxBar',side_effect=AssertionError('hardware')):
                with self.assertRaises(FileExistsError):
                    b.main(['--baseline',str(self.baseline),'--plan',str(self.plan_path),'--bdf','0000:01:00.0','--preflight','--journal',str(path)])
