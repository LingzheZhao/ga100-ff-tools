"""Synthetic independent-validator checks; no CMPGlitch checkout or GPU needed."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import unittest

v = SourceFileLoader('audit_validator', str(Path(__file__).resolve().parents[1]/'validate_cmpglitch.py3')).load_module()

class AuditTests(unittest.TestCase):
    def test_iff_stops_before_later_record(self):
        rows = [0]*225
        rows[222] = (1 << 16) | (5 << 6) | 1
        rows[223] = 0x20
        rows[224] = (2 << 16) | (5 << 6) | 1
        blocks, start, boundary = v.decode(rows)
        self.assertEqual((blocks, start, boundary), ({(1, 5): 1}, 223, 223))
    def test_pri_is_not_interpreted_as_ff(self):
        rows = [0]*224
        rows[222], rows[223] = 0xbadf510c, 0x20
        with self.assertRaisesRegex(ValueError, 'PRI'):
            v.decode(rows)
    def test_boundary_is_required(self):
        with self.assertRaisesRegex(ValueError, 'IFF'):
            v.decode([0]*512)
    def test_other_chains_preserved_reserved_chain_rejected(self):
        rows = [0]*224
        rows[222], rows[223] = (0x1234 << 16) | (17 << 6) | 26, 0x20
        self.assertEqual(v.decode(rows)[0], {(26, 17): 0x1234})
        rows[222] = (0x1234 << 16) | (17 << 6)
        with self.assertRaisesRegex(ValueError, 'reserved'):
            v.decode(rows)
    def test_cross_block_device_id_preserves_adjacent_fields(self):
        blocks = {(2,37):0x4185, (2,38):0x4184, (2,39):0x0782}
        v.set_bits(blocks,2,593,608,0x20b5)
        v.set_bits(blocks,2,609,624,0x20b5)
        self.assertEqual(blocks, {(2,37):0x416b, (2,38):0x416a, (2,39):0x0782})
        self.assertEqual(v.extract(blocks,2,593,608), 0x20b5)
