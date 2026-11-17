"""Synthetic checks for the supplied burn-record findings; no GPU access."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import copy
import json
import tempfile
import unittest

p = SourceFileLoader('conversion_planner', str(Path(__file__).resolve().parents[1]/'ffplan.py3')).load_module()

class ConversionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'capture.json'
        blocks, opts = {}, {'NV_FUSE_CRC_STATUS': 0x55, 'NV_FUSE_OPT_DISABLE_GEN3_SPEED': 1,
                           'NV_FUSE_IFF_RECORD': (507 << 16) | 488}
        for field, (_, _, width, _) in p.FIELDS.items():
            value = 0x20c2 if field in ('PCIE_DEVIDA', 'PCIE_DEVIDB') else (1 << width)-1
            p.edit_field(blocks, field, value)
            opts[p.option_name(field)] = value
        for field in p.DEFECT_REGISTERS:
            opts[p.defect_name(field)] = 5 if field == 'NVLINK_DISABLE' else 0
        blocks[1, 23] = 0x0fef
        opts['NV_FUSE_OPT_SYS_PIPE_DISABLE'] = 0xfe
        blocks[2, 37] |= 1  # Preserve bit0 outside DEVIDA.
        blocks[2, 39] = 0x0782
        blocks[2, 46], blocks[2, 47] = 0xa000, 0x0059
        opts['NV_FUSE_OPT_PCIE_MAGIC_BITS_D'] = 0x16680000
        rows = [0]*512
        for row, ((chain, block), value) in enumerate(sorted(blocks.items()), 222):
            rows[row] = (value << 16) | (block << 6) | chain
        rows[488] = 0x20
        self.capture = {'bdf': '0000:01:00.0', 'pci_device': '0x20c2',
                        'options': [opts.copy(), opts.copy()], 'raw_rows': [rows[:], rows[:]]}
    def plan(self, features, route=None, proof_rows=0):
        self.path.write_text(json.dumps(self.capture))
        if route is None:
            route = 'empirical' if 'pcie-gen4-completion' in features else 'a100' if 'a100-device-id' in features else 'cmp'
        return p.make_plan(self.path, features, route=route, proof_rows=proof_rows)
    def test_completion_combines_bit25_and_preserves_other_bits(self):
        plan = self.plan(['pcie-gen4-bit25', 'pcie-gen4-completion'])
        records = {r['block']: r for r in plan['records']}
        self.assertEqual(set(records), {46, 47})
        self.assertEqual(records[46]['new_block'], 0x8000)
        self.assertEqual(records[47]['new_block'], 0)
        sim = p.simulate(self.path, plan)
        self.assertEqual(sim['register_effects'][-1]['after'], 0x00200000)
        self.assertFalse(sim['register_effects'][-1]['working_gen4_established'])
        self.assertTrue(all(e['per_card_volatile_validation_required'] for e in plan['field_edits'] if 'ff_mask' in e))
    def test_partial_empirical_group_is_rejected(self):
        for rows in self.capture['raw_rows']:
            for i, raw in enumerate(rows):
                if raw & 0xffff == (47 << 6) | 2:
                    rows[i] ^= 1 << 16
        with self.assertRaisesRegex(ValueError, 'empirical MAGIC_D group'):
            self.plan(['pcie-gen4-completion'])
    def test_nvlink_preserves_sys_pipe_and_retains_defective_links(self):
        plan = self.plan(['nvlink'])
        r, = plan['records']
        self.assertEqual((r['chain'], r['block'], r['new_block']), (1, 23, 0x0fed))
        self.assertEqual(p.simulate(self.path, plan)['public_fields']['NVLINK_DISABLE'], 5)
    def test_nvlink_missing_defect_is_not_zero(self):
        for opts in self.capture['options']:
            opts.pop('NV_FUSE_OPT_NVLINK_DEFECTIVE')
        plan = self.plan(['nvlink'])
        self.assertEqual(plan['status'], 'incomplete')
        self.assertEqual(plan['records'], [])
    def test_device_ids_change_only_their_fields(self):
        plan = self.plan(['a100-device-id'])
        records = {r['block']: r for r in plan['records']}
        self.assertEqual(set(records), {37, 38})
        self.assertEqual(records[37]['new_block'], 0x416b)
        self.assertEqual(records[38]['new_block'], 0x416a)
        sim = p.simulate(self.path, plan)
        self.assertEqual(set(sim['public_fields'].values()), {0x20b5})
    def test_all_features_allocate_unique_rows_and_replay(self):
        plan = self.plan(list(p.GROUPS))
        plan = json.loads(json.dumps(plan))  # Saved CLI plans must regenerate exactly.
        self.assertEqual(len({r['row'] for r in plan['records']}), len(plan['records']))
        self.assertEqual(len([r for r in plan['records'] if (r['chain'], r['block']) == (2, 47)]), 1)
        sim = p.simulate(self.path, plan)
        self.assertEqual(sim['register_effects'][-1]['after'], 0x00200000)
        tampered = copy.deepcopy(plan)
        tampered['records'][0]['word'] ^= 1
        with self.assertRaisesRegex(ValueError, 'regeneration'):
            p.simulate(self.path, tampered)
