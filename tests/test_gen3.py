from importlib.machinery import SourceFileLoader
from pathlib import Path
import copy
import json
import tempfile
import unittest

p = SourceFileLoader('local_ffplan', str(Path(__file__).resolve().parents[1]/'ffplan.py3')).load_module()

class Gen3Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'capture.json'
        rows = [0]*512
        rows[222] = (0xa782 << 16) | (39 << 6) | 2
        rows[488] = 0x20
        opts = {'NV_FUSE_CRC_STATUS': 0x55, 'NV_FUSE_OPT_DISABLE_GEN3_SPEED': 1,
                'NV_FUSE_IFF_RECORD': (507 << 16) | 488}
        self.capture = {'bdf': '0000:01:00.0', 'pci_device': '0x20c2',
                        'options': [opts.copy(), opts.copy()], 'raw_rows': [rows[:], rows[:]]}
    def plan(self):
        self.path.write_text(json.dumps(self.capture))
        return p.make_plan(self.path, ['pcie-gen3-pair'])
    def test_pair_preserves_unrelated_bits_and_replays(self):
        plan = self.plan()
        r, = plan['records']
        self.assertEqual((r['old_block'], r['new_block']), (0xa782, 0xa580))
        self.assertEqual(r['old_block'] ^ r['new_block'], 0x0202)
        self.assertFalse(plan['public_sources_only'])
        self.assertIsNone(plan['field_edits'][0]['predicted_speed_disable'])
        sim = p.simulate(self.path, plan)
        self.assertEqual(sim['experimental_fields'][p.GEN3_PAIR['field']]['replayed_block'], 0xa580)
    def test_already_clear_pair_has_no_record(self):
        for rows in self.capture['raw_rows']:
            rows[222] &= ~(0x0202 << 16)
        self.assertEqual(self.plan()['records'], [])
    def test_missing_block_or_shadow_is_incomplete(self):
        for kind in ('block', 'shadow'):
            with self.subTest(kind=kind):
                original = copy.deepcopy(self.capture)
                if kind == 'block':
                    for rows in self.capture['raw_rows']:
                        rows[222] = 0
                else:
                    for opts in self.capture['options']:
                        opts.pop('NV_FUSE_OPT_DISABLE_GEN3_SPEED')
                plan = self.plan()
                self.assertEqual(plan['status'], 'incomplete')
                self.assertEqual(plan['records'], [])
                self.capture = original
    def test_unrelated_bit_tampering_is_rejected(self):
        plan = self.plan()
        plan['records'][0]['new_block'] ^= 0x80
        with self.assertRaisesRegex(ValueError, 'regeneration'):
            p.simulate(self.path, plan)
    def test_block39_requires_opt_in_and_exact_pair(self):
        plan = self.plan()
        rows = dict(enumerate(self.capture['raw_rows'][0]))
        with self.assertRaisesRegex(ValueError, 'explicit'):
            p.validate_records(plan['records'], rows, 223, 488)
        records = copy.deepcopy(plan['records'])
        records[0]['new_block'] ^= 0x80
        records[0]['word'] = (records[0]['new_block'] << 16) | (39 << 6) | 2
        with self.assertRaisesRegex(ValueError, 'preserve'):
            p.validate_records(records, rows, 223, 488, True)
