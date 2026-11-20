from importlib.machinery import SourceFileLoader
from pathlib import Path
import contextlib
import io
import json
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]/'planner'
f = SourceFileLoader('local_ffcard', str(ROOT/'ffcard.py')).load_module()
ps = SourceFileLoader('local_pcie_state', str(ROOT/'pcie_state.py')).load_module()

# Synthetic stock die: every chain-1 field block fully disabled except the
# SYS_PIPE/NVLink block, PCIe blocks at the proven stock values.
STOCK = {(1, b): 0xffff for b in range(5, 23)}
STOCK.update({(1, 23): 0x0fef, (2, 37): 0x8410, (2, 38): 0x0040, (2, 39): 0x0782,
              (2, 46): 0xa000, (2, 47): 0x0059, (2, 49): 0x00e4})
DEFECTS = {'OPT_FBIO_DEFECTIVE': 0xc03000, 'OPT_FBPA_DEFECTIVE': 0xc03000,
           'OPT_GPC_DEFECTIVE': 0, 'OPT_PES_DEFECTIVE': 0, 'OPT_FBP_DEFECTIVE': 0x840,
           'OPT_ROP_L2_DEFECTIVE': 0xc03000, 'OPT_NVLINK_DEFECTIVE': 0,
           **{'OPT_TPC_GPC%d_DEFECTIVE' % i: 0 for i in range(8)}}
DEFECTS['OPT_TPC_GPC6_DEFECTIVE'] = 0x08


def dump(words):
    """ff_dump.py-shaped JSON for rows 222-487 holding these words in order."""
    rows = [{'row': 222 + i, 'raw': '0x%08X' % (words[i] if i < len(words) else 0)}
            for i in range(266)]
    return {'crc_status': '0x55', 'controller_idle': True, 'read_errors': [], 'rows': rows}


def stock_words():
    return [(d << 16) | (b << 6) | c for (c, b), d in sorted(STOCK.items())]


class Cmp170Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.write('stock.json', dump(stock_words()))
        self.write('defects.json', {'registers': [{'name': n, 'value': '0x%08X' % v}
                                                  for n, v in DEFECTS.items()]})

    def write(self, name, obj):
        (self.dir/name).write_text(json.dumps(obj))
        return str(self.dir/name)

    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = f.main([str(a) for a in argv])
        return rc, out.getvalue()

    def derive(self, *extra):
        rc, out = self.run_cli('derive', '--card', 't', '--dump', self.dir/'stock.json',
                               '--defects', self.dir/'defects.json', '--out-dir', self.dir/'plans', *extra)
        self.assertEqual(rc, 0, out)
        return sorted((self.dir/'plans').glob('t_plan_*.json'))

    def records(self, plans):
        recs = [r for p in plans for r in json.loads(p.read_text())['records']]
        return sorted(recs, key=lambda r: r['row'])

    def burned(self, n):
        """Window dump with the first n planned records burned."""
        recs = self.records(sorted((self.dir/'plans').glob('t_plan_*.json')))
        return self.write('window.json', dump(stock_words() + [int(r['encoded'], 16) for r in recs[:n]]))

    def test_derive_only_clears_field_bits_and_never_device_id(self):
        plans = self.derive()
        self.assertEqual([p.name for p in plans], ['t_plan_0_noop.json', 't_plan_nvlink.json',
                                                   't_plan_pcie.json', 't_plan_sm_hbm.json'])
        recs = self.records(plans)
        last = 222 + len(STOCK) - 1
        self.assertEqual([r['row'] for r in recs], list(range(last + 1, last + 1 + len(recs))))
        for r in recs:
            self.assertNotIn((r['chain'], r['block']), f.FORBIDDEN)
            self.assertNotIn('sets_bits', r)
        nv, = json.loads((self.dir/'plans'/'t_plan_nvlink.json').read_text())['records']
        self.assertEqual((nv['old_data'], nv['new_data']), ('0x0FEF', '0x0FE8'))  # SYS_PIPE kept

    def test_skip_rows_leaves_a_blank_buffer(self):
        recs = self.records(self.derive('--skip-rows', '4'))
        self.assertEqual(recs[0]['row'], 222 + len(STOCK) + 4)

    def test_check_resumes_and_verify_passes_after_all_records(self):
        plans = self.derive()
        n = len(self.records(plans))
        rc, out = self.run_cli('check', '--dump', self.burned(0), *plans)
        self.assertEqual(rc, 0, out)
        self.assertIn('--plan t_plan_0_noop.json --index 0', out)
        rc, out = self.run_cli('check', '--dump', self.burned(3), *plans)
        self.assertEqual(rc, 0, out)
        self.assertIn('--plan t_plan_sm_hbm.json --index 2', out)
        rc, out = self.run_cli('verify', '--dump', self.burned(3), *plans)
        self.assertEqual(rc, 1)
        self.assertIn('not burned', out)
        rc, out = self.run_cli('verify', '--dump', self.burned(n), '--defects', self.dir/'defects.json', *plans)
        self.assertEqual(rc, 0, out)
        self.assertIn('VERIFY PASS', out)

    def test_check_stops_on_other_card_wrong_row_or_stray_write(self):
        plans = self.derive()
        other = stock_words()
        other[0] ^= 1 << 16
        rc, out = self.run_cli('check', '--dump', self.write('other.json', dump(other)), *plans)
        self.assertEqual(rc, 1)
        self.assertIn('NOT the planned card', out)
        rc, out = self.run_cli('check', '--dump', self.write('bad.json', dump(stock_words() + [0x12340141])), *plans)
        self.assertEqual(rc, 1)
        self.assertIn('plan 0xFFFF01C1', out)
        recs = self.records(plans)
        words = stock_words() + [int(r['encoded'], 16) for r in recs] + [0x00000141]
        rc, out = self.run_cli('check', '--dump', self.write('stray.json', dump(words)), *plans)
        self.assertEqual(rc, 1)
        self.assertIn('outside the plans', out)

    def test_missing_defect_mask_is_refused_not_zero(self):
        self.write('defects.json', {'registers': [{'name': n, 'value': '0x0'}
                                                  for n in DEFECTS if n != 'OPT_PES_DEFECTIVE']})
        rc, out = self.run_cli('derive', '--card', 't', '--dump', self.dir/'stock.json',
                               '--defects', self.dir/'defects.json', '--out-dir', self.dir/'plans')
        self.assertEqual(rc, 1)
        self.assertIn('OPT_PES_DEFECTIVE', out)

    def test_unexpected_pcie_block_skips_only_the_pcie_plan(self):
        STOCK[(2, 47)] = 0x0058
        self.addCleanup(STOCK.__setitem__, (2, 47), 0x0059)
        self.write('stock.json', dump(stock_words()))
        names = [p.name for p in self.derive()]
        self.assertNotIn('t_plan_pcie.json', names)
        self.assertIn('t_plan_sm_hbm.json', names)

    def test_pcie_state_reads_link_from_capability_list(self):
        cfg = bytearray(256)
        cfg[0x34], cfg[0x60], cfg[0x61], cfg[0x68] = 0x60, 0x01, 0x68, 0x10
        struct.pack_into('<I', cfg, 0x74, (16 << 4) | 4)
        struct.pack_into('<H', cfg, 0x7a, (16 << 4) | 2)
        cap = ps.pcie_cap(bytes(cfg))
        self.assertEqual((ps.link(bytes(cfg), cap + 0x0c), ps.link(bytes(cfg), cap + 0x12)),
                         ('16GT/s x16', '5GT/s x16'))


if __name__ == '__main__':
    unittest.main()
