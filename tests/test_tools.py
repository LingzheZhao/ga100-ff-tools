"""Synthetic fixtures only. No customer dumps, PCI access or real GPU required."""
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    loader = SourceFileLoader(name, str(path))
    module = module_from_spec(spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


c = load('public_capture', ROOT/'capture.py3')
p = load('public_planner', ROOT/'ffplan.py3')


class FakeBar:
    def __init__(self):
        self.address = 7
        self.commands = []
        self.fail_at = None
        self.pri_at = None
        self.bad_address = False
        self.restore_failure = False
        self.regs = {off: 0 for off in c.REGISTERS.values()}
        self.regs.update({c.FUSECTRL: 0xe0040000, c.CRC_STATUS: 0x55, 0: 0x10000001})
        self.regs.update({off: 0xffffffff for name, off in c.CORE.items() if name.endswith('_PLM')})
        self.regs[c.CORE['IFF_RECORD']] = (507 << 16) | 488
        self.regs[c.CORE['DISABLE_SW_OVERRIDE_STATUS']] = 1
        self.regs[c.CORE['ENABLE_FUSE_PROGRAM_STATUS']] = 1
        self.regs[c.OPTIONS['NV_FUSE_OPT_SECURED_BURN_FEATURE_ENABLE']] = 1
        self.regs[c.OPTIONS['NV_FUSE_OPT_PCIE_DEVIDA']] = 0x20c2
        self.regs[c.OPTIONS['NV_FUSE_OPT_PCIE_DEVIDB']] = 0x20c2
        blocks = {}
        for field, (_, _, width, offset) in p.FIELDS.items():
            value = (1 << width)-1
            p.edit_field(blocks, field, value)
            self.regs[offset] = value << 25 if field == 'GEN4_DISABLE' else value
        for field, offset in p.DEFECT_REGISTERS.items():
            self.regs[offset] = 8 if field == 'TPC_GPC6_DISABLE' else 0
        blocks[2, 39] = 0x0782
        self.regs[c.OPTIONS['NV_FUSE_OPT_DISABLE_GEN3_SPEED']] = 1
        self.rows = [0]*512
        for row, ((chain, block), data) in enumerate(sorted(blocks.items()), 222):
            self.rows[row] = (data << 16) | (block << 6) | chain
        self.rows[488] = 0x20  # Synthetic first IFF marker; never interpreted further.

    def rd(self, offset):
        if offset == c.FUSEADDR:
            return self.address+1 if self.bad_address and self.commands else self.address
        if offset == c.FUSEDATA:
            return 0xbadf510c if self.address == self.pri_at else self.rows[self.address]
        return self.regs[offset]

    def select_row(self, row):
        self.commands.append(('address', row))
        self.address = row

    def issue_read(self):
        self.commands.append(('read', c.CMD_READ))
        if self.fail_at == len([x for x in self.commands if x[0] == 'read']):
            raise OSError('synthetic I/O failure')

    def restore_address(self, value):
        if self.restore_failure:
            raise OSError('synthetic restoration failure')
        self.commands.append(('restore', value))
        self.address = value

    def close(self):
        pass


class UUIDTests(unittest.TestCase):
    UUID = 'GPU-12345678-1234-5678-9abc-123456789abc'
    BDF = '0000:01:00.0'

    def test_observed_uuid_matches_selected_bdf(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/self.BDF).mkdir()
            (root/self.BDF/'information').write_text('GPU UUID: '+self.UUID+'\n')
            result = c.observe_gpu_uuid(self.BDF, self.UUID, root)
            self.assertEqual(result['value'], self.UUID)
            self.assertTrue(result['live_verified'])
            self.assertTrue(result['supplied_mapping_matched'])
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                c.observe_gpu_uuid(self.BDF, self.UUID[:-1]+'d', root)

    def test_unbound_uuid_preserves_supplied_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            result = c.observe_gpu_uuid(self.BDF, self.UUID, Path(temp))
            self.assertEqual(result['value'], self.UUID)
            self.assertFalse(result['live_verified'])
            self.assertEqual(result['source'], 'user-supplied BDF mapping')
            self.assertIsNone(c.observe_gpu_uuid(self.BDF, proc_gpus=Path(temp))['value'])

    def test_reject_invalid_or_sentinel_uuid(self):
        for value in ('GPU-short', 'GPU-'+'00000000-0000-0000-0000-000000000000',
                      'GPU-ffffffff-ffff-ffff-ffff-ffffffffffff'):
            with self.assertRaises(ValueError):
                c.validate_gpu_uuid(value)

    def test_identity_mismatch_stops_before_bar_access(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/self.BDF).mkdir()
            (root/self.BDF/'information').write_text('GPU UUID: '+self.UUID+'\n')
            with patch.object(c, 'LinuxBar') as bar:
                result = c.capture_device(self.BDF, gpu_uuid=self.UUID[:-1]+'d', proc_gpus=root)
                self.assertFalse(result['ok'])
                self.assertIn('disagrees', result['error'])
                bar.assert_not_called()


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.io = FakeBar()

    def capture(self, raw=True):
        report = c.new_report('0000:01:00.0', raw)
        report['pci_device'] = '0x20c2'
        c.capture_io(self.io, report, raw)
        return report

    def save(self, name, data):
        path = self.root/name
        path.write_text(json.dumps(data))
        return path

    def test_fuse_command_constants_match_the_protocol(self):
        self.assertEqual((c.CMD_IDLE, c.CMD_READ, c.CMD_WRITE, c.CMD_SENSE), (0, 1, 2, 3))
        self.assertEqual(c.CMD_MASK, 3)

    def test_options_only_issues_no_commands(self):
        report = self.capture(raw=False)
        self.assertTrue(report['ok'])
        self.assertEqual(self.io.commands, [])
        self.assertEqual(report['raw_rows'], [])
        self.assertTrue(report['mmio_read_only'])

    def test_full_capture_restores_address_and_reads_twice(self):
        report = self.capture()
        self.assertEqual([len(x) for x in report['raw_rows']], [512, 512])
        self.assertEqual(sum(x[0] == 'read' for x in self.io.commands), 1024)
        self.assertEqual(self.io.address, 7)
        self.assertTrue(report['raw_address_restored'])
        self.assertTrue(report['raw_match'])

    def test_capture_to_plan_to_replay(self):
        baseline = self.save('capture.json', self.capture())
        plan = p.make_plan(baseline, ['memory', 'compute'])
        self.assertEqual(plan['status'], 'logical-plan-complete')
        result = p.simulate(baseline, plan)
        self.assertEqual(result['public_fields']['TPC_GPC6_DISABLE'], 8)
        self.assertFalse(result['programming_eligibility_established'])

    def test_crc_failure_has_no_commands(self):
        self.io.regs[c.CRC_STATUS] = 0
        with self.assertRaisesRegex(ValueError, 'CRC_STATUS'):
            self.capture()
        self.assertEqual(self.io.commands, [])

    def test_debug_mode_refused_without_changing_it(self):
        self.io.regs[c.FUSEDEBUG] = 2
        with self.assertRaisesRegex(ValueError, 'FUSEDEBUG'):
            self.capture()
        self.assertEqual(self.io.commands, [])
        self.assertEqual(self.io.regs[c.FUSEDEBUG], 2)

    def test_busy_controller_no_commands(self):
        self.io.regs[c.FUSECTRL] = 0x000c0000
        with self.assertRaisesRegex(ValueError, 'IDLE'):
            self.capture()
        self.assertEqual(self.io.commands, [])

    def test_partial_pass_survives_io_failure(self):
        report = c.new_report('0000:01:00.0', True)
        self.io.fail_at = 4
        with self.assertRaises(OSError):
            c.capture_io(self.io, report, True)
        self.assertEqual(len(report['raw_rows'][0]), 3)
        self.assertEqual(self.io.address, 7)
        self.assertFalse(report['ok'])

    def test_pri_response_is_not_fuse_data(self):
        report = c.new_report('0000:01:00.0', True)
        self.io.pri_at = 3
        with self.assertRaisesRegex(ValueError, 'PRI error'):
            c.capture_io(self.io, report, True)
        self.assertEqual(len(report['raw_rows'][0]), 3)
        self.assertEqual(self.io.address, 7)

    def test_address_readback_failure_stops_commands(self):
        self.io.bad_address = True
        with self.assertRaisesRegex(ValueError, 'did not latch'):
            self.capture()
        self.assertFalse(any(x[0] == 'read' for x in self.io.commands))

    def test_restore_failure_invalidates_capture(self):
        self.io.restore_failure = True
        report = c.new_report('0000:01:00.0', True)
        with self.assertRaisesRegex(ValueError, 'restore'):
            c.capture_io(self.io, report, True)
        self.assertFalse(report['raw_address_restored'])
        self.assertIn('restore_error', report)

    def test_default_linux_mapping_is_readonly(self):
        dev = self.root/'0000:01:00.0'
        dev.mkdir()
        (dev/'resource0').write_bytes(b'\0'*c.MAP_SIZE)
        real_open = c.os.open
        opened = []
        def open_fd(path, flags):
            opened.append(flags)
            return real_open(path, flags)
        with patch('builtins.open', return_value=tempfile.TemporaryFile()), patch('fcntl.flock'), patch.object(c.os, 'open', side_effect=open_fd):
            bar = c.LinuxBar(dev, writable=False)
            with self.assertRaisesRegex(ValueError, 'Read-only'):
                bar.issue_read()
            bar.close()
        self.assertEqual(opened[0] & c.os.O_ACCMODE, c.os.O_RDONLY)

    def test_adapter_rejects_programming_and_other_ports(self):
        bar = object.__new__(c.LinuxBar)
        bar.writable = True
        bar.dev = self.root/'unbound'
        for offset, value in [(c.FUSECTRL, c.CMD_WRITE), (c.FUSECTRL, c.CMD_SENSE), (0x82000c, 1), (0x100, 1), (c.FUSEADDR, 512)]:
            with self.assertRaisesRegex(ValueError, 'only physical'):
                bar._write(offset, value)

    def test_option_only_capture_has_no_guess_for_missing_rows(self):
        plan = p.make_plan(self.save('options.json', self.capture(False)), ['memory'])
        self.assertEqual(plan['status'], 'incomplete')
        self.assertEqual(plan['records'], [])

    def test_missing_defect_mask_never_defaults_to_zero(self):
        report = self.capture()
        for sample in report['options']:
            del sample['NV_FUSE_OPT_FBP_DEFECTIVE']
        plan = p.make_plan(self.save('capture.json', report), ['memory'])
        field = next(x for x in plan['field_edits'] if x['field'] == 'FBP_DISABLE')
        self.assertIsNone(field['target'])
        self.assertEqual(plan['records'], [])

    def test_first_iff_terminates_replay(self):
        rows = {222: (1 << 16) | (5 << 6) | 1, 223: 0x20, 224: 0xbadf510c}
        blocks, _, boundary = p.decode(rows)
        self.assertEqual(boundary, 223)
        self.assertEqual(blocks, {(1, 5): 1})

    def test_type_bit_with_nonzero_payload_and_chain_ends_ff(self):
        marker=0xabcd05e7  # Bit5 set, plus a nonzero payload, block and chain.
        rows={222:(1<<16)|(5<<6)|1,223:marker,224:(2<<16)|(5<<6)|1}
        blocks,_,boundary=p.decode(rows)
        self.assertEqual(boundary,223)
        self.assertEqual(blocks,{(1,5):1})
        observed=c.ff_boundary_observation([0]*222+[rows[222],marker,rows[224]])
        self.assertEqual(observed['first_iff_row'],223)
        self.assertEqual(observed['first_iff_word'],'0xabcd05e7')

    def test_eight_zero_rows_do_not_invent_an_iff_boundary(self):
        rows={row:0 for row in range(222,234)}
        rows[222]=(1<<16)|(5<<6)|1
        rows[231]=(2<<16)|(5<<6)|1
        rows[233]=1<<5
        blocks,start,boundary=p.decode(rows)
        self.assertEqual((blocks,start,boundary),({(1,5):2},232,233))

    def test_early_iff_boundary_rejects_insufficient_ff_capacity(self):
        # Push the last occupied FF row to 303, then put IFF at 310, not 488.
        self.io.rows[303]=next(value for value in self.io.rows if value and value&31==2 and not value&32)
        self.io.rows[310]=0x12340020
        self.io.regs[c.CORE['IFF_RECORD']] = (329 << 16) | 310
        report=self.capture()
        self.assertEqual(report['ff_boundary_observation']['first_iff_row'],310)
        self.assertEqual(report['ff_boundary_observation']['trailing_blank_rows'],6)
        with self.assertRaisesRegex(ValueError,'Insufficient observed trailing FF space'):
            p.make_plan(self.save('early-iff.json',report),['memory','compute'])

    def test_plan_exposes_observed_boundary_and_remaining_space(self):
        plan=p.make_plan(self.save('capture.json',self.capture()),['memory','compute'])
        evidence=plan['ff_boundary_evidence']
        self.assertEqual(evidence['first_iff_row'],488)
        self.assertEqual(evidence['first_iff_word'],1<<5)
        self.assertEqual(evidence['remaining_blank_rows_after_plan'],
                         evidence['observed_trailing_blank_rows']-4-len(plan['records']))
        self.assertTrue(evidence['iff_register_checked'])
        self.assertFalse(evidence['eight_zero_rule_assumed'])
        self.assertEqual(evidence['software_reserved_rows'],16)

    def test_missing_or_ambiguous_type_boundary_is_not_guessed(self):
        self.assertEqual(c.ff_boundary_observation([0]*512)['status'],'not-observed')
        rows=[0]*512;rows[300]=0xffffffff
        self.assertEqual(c.ff_boundary_observation(rows)['status'],'ambiguous')
        for row,value in enumerate(self.io.rows):
            if value&32:self.io.rows[row]=0
        plan=p.make_plan(self.save('missing-iff.json',self.capture()),['memory'])
        self.assertEqual(plan['status'],'incomplete')
        self.assertEqual(plan['records'],[])
        self.assertIsNone(plan['iff_boundary'])

    def test_cross_card_plan_rejected(self):
        report = self.capture()
        first = self.save('first.json', report)
        plan = p.make_plan(first, ['memory'])
        report = copy.deepcopy(report)
        report['bdf'] = '0000:02:00.0'
        for rows in report['raw_rows']:
            rows[200] = '0x00000001'
        with self.assertRaisesRegex(ValueError, 'regeneration'):
            p.simulate(self.save('second.json', report), plan)

    def test_gen3_ambiguous_block_not_edited(self):
        plan = p.make_plan(self.save('capture.json', self.capture()), ['pcie-known'])
        self.assertEqual({x['block'] for x in plan['records']}, {47, 49})

    def test_bit25_feature_preserves_other_register_and_ff_bits(self):
        # Arbitrary synthetic register/block patterns, not a measured card.
        self.io.regs[c.OPTIONS['NV_FUSE_OPT_PCIE_MAGIC_BITS_D']] = 0x5a123456
        for row, encoded in enumerate(self.io.rows):
            if encoded & 0xffff == (47 << 6) | 2:
                self.io.rows[row] = (0xa559 << 16) | (47 << 6) | 2
        baseline = self.save('capture.json', self.capture())
        plan = p.make_plan(baseline, ['pcie-gen4-bit25'])
        self.assertEqual(len(plan['records']), 1)
        record = plan['records'][0]
        self.assertEqual((record['chain'], record['block']), (2, 47))
        self.assertEqual((record['old_block'], record['new_block']), (0xa559, 0xa551))
        self.assertEqual(record['old_block'] ^ record['new_block'], 1 << 3)
        edit = plan['field_edits'][0]
        self.assertEqual(edit['public_field'], 'NV_FUSE_OPT_PCIE_MAGIC_BITS_D[25]')
        self.assertEqual(edit['register_mask'], 0x02000000)
        result = p.simulate(baseline, plan)
        effect = result['register_effects'][0]
        self.assertEqual(effect['before'], 0x5a123456)
        self.assertEqual(effect['after'], 0x58123456)
        self.assertTrue(effect['unrelated_register_bits_preserved'])
        self.assertFalse(effect['working_gen4_established'])

    def test_already_cleared_bit25_needs_no_new_record(self):
        self.io.regs[c.OPTIONS['NV_FUSE_OPT_PCIE_MAGIC_BITS_D']] &= ~0x02000000
        for row, encoded in enumerate(self.io.rows):
            if encoded & 0xffff == (47 << 6) | 2:
                self.io.rows[row] &= ~(1 << (16+3))
        baseline = self.save('capture.json', self.capture())
        plan = p.make_plan(baseline, ['pcie-gen4-bit25'])
        self.assertEqual(plan['records'], [])
        self.assertEqual(p.simulate(baseline, plan)['register_effects'][0]['bit_after'], 0)

    def test_bit25_mapping_conflict_is_rejected(self):
        self.io.regs[c.OPTIONS['NV_FUSE_OPT_PCIE_MAGIC_BITS_D']] &= ~0x02000000
        baseline = self.save('capture.json', self.capture())
        with self.assertRaisesRegex(ValueError, 'mapping does not match'):
            p.make_plan(baseline, ['pcie-gen4-bit25'])

    def test_overlapping_pcie_features_do_not_duplicate_bit25(self):
        baseline = self.save('capture.json', self.capture())
        plan = p.make_plan(baseline, ['pcie-known', 'pcie-gen4-bit25'])
        self.assertEqual(sum(e['field'] == 'GEN4_DISABLE' for e in plan['field_edits']), 1)
        self.assertEqual({r['block'] for r in plan['records']}, {47, 49})

    def test_memory_compute_and_bit25_are_allocated_together(self):
        baseline = self.save('capture.json', self.capture())
        memory = p.make_plan(baseline, ['memory', 'compute'])
        combined = p.make_plan(baseline, ['memory', 'compute', 'pcie-gen4-bit25'])
        self.assertEqual(len(combined['records']), len(memory['records'])+1)
        self.assertEqual(len({r['row'] for r in combined['records']}), len(combined['records']))
        self.assertEqual(p.simulate(baseline, combined)['register_effects'][0]['bit_after'], 0)

    def test_plan_tampering_rejected(self):
        baseline = self.save('capture.json', self.capture())
        plan = p.make_plan(baseline, ['memory'])
        plan['records'][0]['word'] ^= 1
        with self.assertRaisesRegex(ValueError, 'regeneration'):
            p.simulate(baseline, plan)

    def test_no_dependency_on_other_project_folders(self):
        for module, name in [(c, 'capture.py3'), (p, 'ffplan.py3')]:
            path = self.root/name
            path.write_bytes((ROOT/name).read_bytes())
            standalone = load('standalone_'+name.split('.')[0], path)
            self.assertTrue(callable(standalone.main))

    def test_deadline_stops_raw_reads_and_restores_address(self):
        report = c.new_report('0000:01:00.0', True)
        with self.assertRaisesRegex(ValueError, 'deadline'):
            c.read_rows(self.io, report, total_timeout=1e-12)
        self.assertEqual(self.io.address, 7)
        self.assertFalse(any(x[0] == 'read' for x in self.io.commands))

    def test_cli_plan_and_simulation_accept_public_capture(self):
        baseline = self.save('capture.json', self.capture())
        plan_file = self.root/'plan.json'
        self.assertEqual(p.main(['plan', '--baseline', str(baseline), '--output', str(plan_file)]), 0)
        plan = json.loads(plan_file.read_text())
        self.assertEqual(set(plan['features']), {'memory', 'compute', 'pcie-gen3-pair'})
        self.assertTrue(any(r['chain'] == 2 and r['block'] == 39 for r in plan['records']))
        self.assertEqual(p.simulate(baseline, plan)['records_applied'], len(plan['records']))

    def test_existing_output_is_not_overwritten(self):
        baseline = self.save('capture.json', self.capture())
        output = self.root/'plan.json'
        output.write_text('preserve existing output')
        with self.assertRaises(FileExistsError):
            p.main(['plan', '--baseline', str(baseline), '--output', str(output)])
        self.assertEqual(output.read_text(), 'preserve existing output')


if __name__ == '__main__':
    unittest.main()
