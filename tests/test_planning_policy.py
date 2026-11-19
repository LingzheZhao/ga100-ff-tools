"""Planning policy regressions. Synthetic captures only; no device operations."""
import copy
import json
import unittest

import test_conversion as fixtures
from test_tools import c, FakeBar

p = fixtures.p


class PlanningPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ConversionTests('test_all_features_allocate_unique_rows_and_replay')
        self.fixture.setUp()
        self.addCleanup(self.fixture.temp.cleanup)

    def test_catalog_exposes_supported_and_unsupported_changes(self):
        catalog = {item['id']: item for item in p.change_catalog()}
        self.assertEqual(set(catalog), set(p.GROUPS) | set(p.UNSUPPORTED_CHANGES))
        self.assertEqual(catalog['pcie-gen4-completion']['allowed_routes'], ['empirical'])
        for name in ('ecc', 'nvdec', 'sm-speed'):
            self.assertFalse(catalog[name]['selectable'])
            with self.assertRaisesRegex(ValueError, 'Invalid feature'):
                self.plan([name])

    def test_change_list_merges_shared_rows_and_simulates_targets(self):
        plan = self.plan(['nvlink', 'sys-pipe'])
        self.assertEqual(len(plan['records']), 1)
        self.assertEqual(len(plan['proposed_changes']), 2)
        for change in plan['proposed_changes']:
            self.assertEqual(change['record_rows'], [plan['records'][0]['row']])
            self.assertEqual(change['record_count_including_shared'], 1)
            self.assertFalse(change['working_capability_verified'])
        sim = p.simulate(self.fixture.path, plan)
        for change in sim['proposed_changes']:
            self.assertEqual(change['status'], 'logical-target-replayed')
            self.assertTrue(all(field['target_replayed'] for field in change['fields']))
            self.assertFalse(change['working_capability_verified'])

    def test_incomplete_change_list_never_reports_executable_rows(self):
        for snapshot in self.fixture.capture['options']:
            del snapshot['NV_FUSE_IFF_RECORD']
        plan = self.plan(['memory', 'compute'])
        for change in plan['proposed_changes']:
            self.assertEqual(change['status'], 'incomplete')
            self.assertEqual(change['record_rows'], [])

    def test_changes_cli_and_feature_alias(self):
        from contextlib import redirect_stdout
        import io
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(p.main(['changes']), 0)
        self.assertEqual(json.loads(output.getvalue())['changes'], p.change_catalog())
        self.fixture.path.write_text(json.dumps(self.fixture.capture))
        plans = []
        for option in ('--changes', '--features'):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(p.main(['plan', '--baseline', str(self.fixture.path), option, 'memory']), 0)
            plans.append(json.loads(output.getvalue()))
        self.assertEqual(plans[0], plans[1])

    def test_tampered_change_list_rejected_by_simulator(self):
        plan = self.plan(['memory'])
        plan['proposed_changes'][0]['fields'][0]['target'] ^= 1
        with self.assertRaisesRegex(ValueError, 'regeneration'):
            p.simulate(self.fixture.path, plan)

    def change_option(self, name, value):
        for sample in self.fixture.capture['options']:
            sample[name] = value

    def plan(self, features, route='cmp', proof_rows=0):
        self.fixture.path.write_text(json.dumps(self.fixture.capture))
        return p.make_plan(self.fixture.path, features, route=route, proof_rows=proof_rows)

    def set_field(self, field, value):
        for rows in self.fixture.capture['raw_rows']:
            blocks, _, _ = p.decode(rows)
            p.edit_field(blocks, field, value)
            for row in range(222, 488):
                raw = rows[row]
                if raw:
                    key = raw & 31, (raw >> 6) & 1023
                    rows[row] = (blocks[key] << 16) | (key[1] << 6) | key[0]
        self.change_option(p.option_name(field), value)

    def test_boundary_register_missing_never_inferred_from_raw_marker(self):
        for sample in self.fixture.capture['options']:
            del sample['NV_FUSE_IFF_RECORD']
        plan = self.plan(['memory'])
        self.assertEqual(plan['status'], 'incomplete')
        self.assertEqual(plan['records'], [])
        self.assertFalse(plan['ff_boundary_evidence']['iff_register_checked'])
        self.assertTrue(any('IFF_RECORD' in item for item in plan['missing_evidence']))

    def test_boundary_mismatch_or_invalid_range_rejected(self):
        for value in (0, (487 << 16) | 488, (507 << 16) | 331):
            with self.subTest(value=value):
                self.change_option('NV_FUSE_IFF_RECORD', value)
                with self.assertRaisesRegex(ValueError, 'IFF_RECORD'):
                    self.plan(['memory'])

    def test_boundary_register_repeat_mismatch_is_rejected(self):
        self.fixture.capture['options'][1]['NV_FUSE_IFF_RECORD'] ^= 1
        with self.assertRaisesRegex(ValueError, 'passes disagree'):
            self.plan(['memory'])

    def test_last_field_inclusive_can_be_row511(self):
        self.change_option('NV_FUSE_IFF_RECORD', (511 << 16) | 488)
        plan = self.plan(['memory'])
        self.assertTrue(plan['ff_boundary_evidence']['iff_register_checked'])
        self.assertEqual(plan['ff_boundary_evidence']['iff_last'], 511)

    def test_sys_pipe_and_nvlink_merge_preserving_bit3(self):
        self.change_option('NV_FUSE_OPT_NVLINK_DEFECTIVE', 0)
        plan = self.plan(['sys-pipe', 'nvlink'])
        record, = plan['records']
        self.assertEqual((record['chain'], record['block'], record['new_block']), (1, 23, 8))
        sim = p.simulate(self.fixture.path, plan)
        self.assertEqual(sim['public_fields']['SYS_PIPE_DISABLE'], 0)
        self.assertFalse(sim['working_features_verified'])

    def test_sys_pipe_retains_its_own_defects_and_other_fields(self):
        self.change_option('NV_FUSE_OPT_SYS_PIPE_DEFECTIVE', 0x40)
        plan = self.plan(['sys-pipe'])
        self.assertEqual(plan['records'][0]['new_block'], 0x40f)
        self.assertEqual(plan['records'][0]['old_block'] & 0xf, 0xf)

    def test_missing_sys_pipe_defect_never_defaults_to_zero(self):
        for sample in self.fixture.capture['options']:
            del sample['NV_FUSE_OPT_SYS_PIPE_DEFECTIVE']
        plan = self.plan(['sys-pipe'])
        self.assertEqual(plan['status'], 'incomplete')
        self.assertEqual(plan['records'], [])

    def test_compute_only_with_unresolved_rop_is_incomplete(self):
        plan = self.plan(['compute'])
        self.assertEqual(plan['status'], 'incomplete')
        self.assertEqual(plan['records'], [])
        self.assertTrue(any('compute dependency ROP_L2' in item for item in plan['missing_evidence']))
        complete = self.plan(['memory', 'compute'])
        self.assertTrue(all(check['satisfied'] for check in complete['dependency_checks']))
        self.assertEqual(complete['status'], 'logical-plan-complete')

    def test_compute_only_allowed_when_rop_already_at_defect_target(self):
        self.set_field('ROP_L2_DISABLE', 0)
        plan = self.plan(['compute'])
        self.assertEqual(plan['status'], 'logical-plan-complete')
        self.assertTrue(all(check['satisfied'] for check in plan['dependency_checks']))

    def test_cmp_route_does_not_allow_identity_or_extra_magic(self):
        for feature in ('a100-device-id', 'pcie-gen4-completion'):
            with self.subTest(feature=feature), self.assertRaisesRegex(ValueError, 'route'):
                self.plan([feature])

    def test_a100_route_preserves_extra_magic_groups(self):
        plan = self.plan(['memory', 'compute', 'pcie-known', 'a100-device-id'], route='a100')
        self.assertFalse(any(r['chain'] == 2 and r['block'] == 46 for r in plan['records']))
        record = next(r for r in plan['records'] if (r['chain'], r['block']) == (2, 47))
        self.assertEqual(record['new_block'], 0x51)
        self.assertEqual(p.simulate(self.fixture.path, plan)['register_effects'][-1]['after'], 0x14680000)
        with self.assertRaisesRegex(ValueError, 'empirical'):
            self.plan(['a100-device-id', 'pcie-gen4-completion'], route='a100')

    def test_empirical_route_is_explicit_and_roundtrips(self):
        plan = self.plan(['pcie-gen4-completion'], route='empirical', proof_rows=2)
        sim = p.simulate(self.fixture.path, json.loads(json.dumps(plan)))
        self.assertEqual(sim['route'], 'empirical')
        self.assertEqual(sim['register_effects'][-1]['after'], 0x200000)

    def test_space_budget_includes_proofs_restores_and_margin(self):
        plan = self.plan(['memory', 'compute'], proof_rows=2)
        count = len(plan['records'])
        budget = plan['space_budget']
        self.assertEqual(budget['required_rows'], 4+2*count+2+16)
        self.assertEqual(budget['restore_rows_reserved'], count)
        self.assertEqual(plan['proof_preview']['rows_reserved'], 2)
        self.assertFalse(plan['proof_preview']['records_generated'])
        self.assertFalse(plan['restoration_preview']['rows_allocated'])
        self.assertEqual(len(plan['restoration_preview']['blocks']), count)
        for record, restoration in zip(plan['records'], plan['restoration_preview']['blocks']):
            self.assertEqual(restoration['original_data'], record['old_block'])

    def test_four_blank_rows_before_first_record_and_replay(self):
        plan = self.plan(['memory', 'compute'])
        rows = self.fixture.capture['raw_rows'][0]
        _, start, boundary = p.decode(rows)
        self.assertEqual(plan['records'][0]['row'], start+4)
        self.assertEqual(plan['space_budget']['append_buffer_rows'], 4)
        self.assertEqual(plan['ff_boundary_evidence']['first_planned_row'], start+4)
        self.assertEqual(plan['ff_boundary_evidence']['remaining_blank_rows_after_plan'],
                         boundary-start-4-len(plan['records']))
        after = dict(enumerate(rows)) if isinstance(rows, list) else dict(rows)
        for record in plan['records']:
            after[record['row']] = record['word']
        self.assertEqual([after[row] for row in range(start, start+4)], [0]*4)
        p.simulate(self.fixture.path, plan)

    def test_records_in_buffer_rejected_and_old_plan_cannot_replay(self):
        plan = self.plan(['nvlink'])
        rows = self.fixture.capture['raw_rows'][0]
        _, start, boundary = p.decode(rows)
        rows = dict(enumerate(rows)) if isinstance(rows, list) else rows
        for row in range(start, start+4):
            changed = copy.deepcopy(plan)
            changed['records'][0]['row'] = row
            with self.assertRaisesRegex(ValueError, 'Invalid or duplicate append row'):
                p.validate_records(changed['records'], rows, start, boundary)
            with self.assertRaisesRegex(ValueError, 'regeneration'):
                p.simulate(self.fixture.path, changed)
        occupied = dict(rows)
        occupied[start+2] = 1
        with self.assertRaisesRegex(ValueError, 'buffer rows were not observed blank'):
            p.validate_records(plan['records'], occupied, start, boundary)

    def test_proof_candidates_are_untouched_unallocated_logical_noops(self):
        plan = self.plan(['memory', 'compute'], proof_rows=2)
        old, _, _ = p.decode(self.fixture.capture['raw_rows'][0])
        touched = {(record['chain'], record['block']) for record in plan['records']}
        candidates = plan['proof_preview']['candidates']
        self.assertTrue(candidates)
        for candidate in candidates:
            key = candidate['chain'], candidate['block']
            self.assertNotIn(key, touched)
            self.assertEqual(candidate['data'], old[key])
            self.assertEqual(candidate['word'], (old[key] << 16) | (key[1] << 6) | key[0])
            self.assertIsNone(candidate['row'])
            self.assertTrue(candidate['logical_no_op_verified'])
            self.assertFalse(candidate['physical_no_op_established'])

    def test_tight_pool_accounts_for_restore_and_proof_rows(self):
        rows = self.fixture.capture['raw_rows'][0]
        _, start, _ = p.decode(rows)
        boundary = start+4+1+1+16+2  # Four buffer, one functional, one restore, two proofs, sixteen spare.
        for values in self.fixture.capture['raw_rows']:
            values[boundary] = 0x20
        self.change_option('NV_FUSE_IFF_RECORD', ((boundary+8) << 16) | boundary)
        plan = self.plan(['nvlink'], proof_rows=2)
        self.assertEqual(plan['space_budget']['remaining_after_all_reservations'], 0)
        with self.assertRaisesRegex(ValueError, 'proof, restore'):
            self.plan(['nvlink'], proof_rows=3)

    def test_invalid_proof_reservation_rejected(self):
        for value in (-1, True, 513):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'proof-row'):
                self.plan(['nvlink'], proof_rows=value)

    def test_checkpoints_never_claim_bootable_or_resumable(self):
        plan = self.plan(['memory', 'compute'])
        checkpoints = plan['cold_boot_checkpoints']
        self.assertEqual(len(checkpoints), len(plan['records']))
        self.assertTrue(all(not item['cold_boot_verified'] and not item['bootability_established'] for item in checkpoints))
        self.assertTrue(all(item['fresh_capture_required_before_followup'] for item in checkpoints))
        self.assertTrue(any(not check['satisfied'] for check in checkpoints[0]['compute_dependencies']))
        self.assertTrue(all(check['satisfied'] for check in checkpoints[-1]['compute_dependencies']))
        sim = p.simulate(self.fixture.path, plan)
        self.assertEqual(sim['cold_boot_checkpoints'], checkpoints)

    def test_policy_tampering_rejected_by_regeneration(self):
        plan = self.plan(['nvlink'], proof_rows=2)
        for key in ('space_budget', 'cold_boot_checkpoints', 'restoration_preview'):
            changed = copy.deepcopy(plan)
            changed[key] = {}
            with self.subTest(key=key), self.assertRaises(ValueError):
                p.simulate(self.fixture.path, changed)

    def test_capture_reads_iff_and_sys_pipe_defect_twice(self):
        fake = FakeBar()
        reads, original = [], fake.rd
        def rd(offset):
            reads.append(offset)
            return original(offset)
        fake.rd = rd
        report = c.new_report('0000:01:00.0', True)
        c.capture_io(fake, report, True)
        self.assertEqual(reads.count(0x820050), 2)
        self.assertEqual(reads.count(0x8203ac), 2)
        self.assertTrue(report['ff_boundary_observation']['iff_register_checked'])
        self.assertEqual(report['ff_boundary_observation']['iff_start'], 488)
        self.assertEqual(report['ff_boundary_observation']['iff_last'], 507)
