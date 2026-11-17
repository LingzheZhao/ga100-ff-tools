#!/usr/bin/env python3
"""GA100 FF planner and logical replay simulator.

Standalone, standard library only. Uses Kate's published FF table and public
register maps, plus explicitly labeled reference toolkit experimental findings.
No private physical aliases, GPIO/supply model, MMIO or hardware
backend. Inputs are captures; outputs are experimental planning evidence, not
programming authorization. Option-only captures can produce an incomplete plan.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

BLOG = 'https://blog.kate.land/posts/using-voltage-glitching-to-unlock-the-a100/'
OPTIONS_SOURCE = 'https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/ga100-options.json'
CORE_SOURCE = 'https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/ga100-core.json'
FF_TYPE_BIT = 5
IFF_TYPE_MASK = 1 << FF_TYPE_BIT
FF_CHAIN_MASK = IFF_TYPE_MASK - 1
SPARE_FF_ROWS = 16  # Software policy; not a verified hardware minimum.
IFF_RECORD_OFFSET = 0x820050
ROUTES = ('cmp', 'a100', 'empirical')
# name: chain, first bit, width, public option register address.
# The locations are empirical mappings published by Kate, not official mappings.
FIELDS = {
    'FBIO_DISABLE': (1, 83, 24, 0x82036c),
    'FBPA_DISABLE': (1, 107, 24, 0x820368),
    'GPC_DISABLE': (1, 131, 8, 0x820350),
    'TPC_GPC0_DISABLE': (1, 187, 8, 0x820760),
    'TPC_GPC1_DISABLE': (1, 195, 8, 0x820764),
    'TPC_GPC2_DISABLE': (1, 203, 8, 0x820768),
    'TPC_GPC3_DISABLE': (1, 211, 8, 0x82076c),
    'TPC_GPC4_DISABLE': (1, 219, 8, 0x820770),
    'TPC_GPC5_DISABLE': (1, 227, 8, 0x820774),
    'TPC_GPC6_DISABLE': (1, 235, 8, 0x820778),
    'TPC_GPC7_DISABLE': (1, 243, 8, 0x82077c),
    'PES_DISABLE': (1, 251, 24, 0x820690),
    'FBP_DISABLE': (1, 307, 12, 0x820364),
    'ROP_L2_DISABLE': (1, 319, 24, 0x8202c4),
    'NVLINK_DISABLE': (1, 23*16, 3, 0x820684),
    'SYS_PIPE_DISABLE': (1, 372, 8, 0x8203a4),
    'PCIE_DEVIDA': (2, 37*16+1, 16, 0x8204d8),
    'PCIE_DEVIDB': (2, 38*16+1, 16, 0x82056c),
    'GEN4_DISABLE': (2, 47*16+3, 1, 0x820520),
    'PCIE_BOOT_GEN23_DISABLE': (2, 49*16+6, 1, 0x82057c),
    'PCIE_BOOT_GEN3_DISABLE': (2, 49*16+7, 1, 0x820580),
}
# Defect register ADDRESSES are public; their physical fuse-row aliases are not used.
DEFECT_REGISTERS = {
    'NVLINK_DISABLE': 0x82068c, 'SYS_PIPE_DISABLE': 0x8203ac,
    'FBIO_DISABLE': 0x8205d4, 'FBPA_DISABLE': 0x8205d0,
    'GPC_DISABLE': 0x8205c4, 'PES_DISABLE': 0x820698,
    'FBP_DISABLE': 0x8205cc, 'ROP_L2_DISABLE': 0x8205e8,
    'TPC_GPC0_DISABLE': 0x8205c8, 'TPC_GPC1_DISABLE': 0x820508,
    'TPC_GPC2_DISABLE': 0x82050c, 'TPC_GPC3_DISABLE': 0x820514,
    'TPC_GPC4_DISABLE': 0x820564, 'TPC_GPC5_DISABLE': 0x8205ac,
    'TPC_GPC6_DISABLE': 0x820b84, 'TPC_GPC7_DISABLE': 0x820b80,
}
GROUPS = {
    'memory': ('FBIO_DISABLE', 'FBPA_DISABLE', 'FBP_DISABLE', 'ROP_L2_DISABLE'),
    'compute': ('GPC_DISABLE', 'PES_DISABLE', *(f'TPC_GPC{i}_DISABLE' for i in range(8))),
    'nvlink': ('NVLINK_DISABLE',),
    'sys-pipe': ('SYS_PIPE_DISABLE',),
    'a100-device-id': ('PCIE_DEVIDA', 'PCIE_DEVIDB'),
    'pcie-gen4-completion': ('GEN4_DISABLE',),
    'pcie-gen3-pair': (),  # Local reference toolkit experiment, not a public bit mapping.
    'pcie-gen4-bit25': ('GEN4_DISABLE',),
    'pcie-known': ('GEN4_DISABLE', 'PCIE_BOOT_GEN23_DISABLE', 'PCIE_BOOT_GEN3_DISABLE'),
}
GATE_FIELDS = frozenset(GROUPS['pcie-known'])
GEN4_REGISTER_BIT = {
    'public_field': 'NV_FUSE_OPT_PCIE_MAGIC_BITS_D[25]',
    'register_offset': 0x820520, 'register_bit': 25, 'register_mask': 0x02000000,
    'ff_chain': 2, 'ff_block': 47, 'ff_bit': 3,
    'set_meaning': 'Gen4 speed disabled',
    'clear_meaning': 'This Gen4 restriction cleared; working Gen4 is not established',
}


GEN3_PAIR = {
    'field': 'GEN3_SPEED_GATE_CANDIDATE_PAIR',
    'ff_chain': 2, 'ff_block': 39, 'ff_bits': [1, 9], 'ff_mask': 0x0202,
    'evidence_source': 'Discord user xPatrik: supplied Gen3 burn record and PCIe derivation notes',
    'evidence_kind': 'local experimental combined change',
    'individual_bit_identity_resolved': False,
    'working_gen3_established': False,
}


MAGIC_COMPLETION = (
    {'field': 'MAGIC_D_BIT19_COMPLETION', 'ff_chain': 2, 'ff_block': 46,
     'ff_mask': 0x2000, 'register_mask': 0x00080000},
    {'field': 'MAGIC_D_BITS22_26_28_COMPLETION', 'ff_chain': 2, 'ff_block': 47,
     'ff_mask': 0x0051, 'register_mask': 0x14400000},
)
EXPERIMENTAL_FEATURES = frozenset(('pcie-gen3-pair', 'pcie-gen4-completion', 'a100-device-id', 'sys-pipe'))
CONVERSION_FINDINGS = {
    'source': 'User-supplied CMP 170HX -> A100-80G FF Burn Record, passes 1-6',
    'scope': 'One reference die; original rows and defect values are not targets for other cards',
    'gen4_completion': 'Reference-die mapping, not universal: an A100-ROM path reportedly trains Gen4 with 0x14680000; empirical route only',
    'sys_pipe': 'Supplied notes report MIG enumeration only; NVDEC has a separate unmapped disable field; ECC/media operation unproven',
    'gen4_group': 'Block47 bits 0,4,6 jointly map to MAGIC_D bits22,26,28; individual permutation unknown',
    'device_id': '20c2 -> 20b5 requires matching signed A100 ROM; CMP ROM may POST but is not functional',
    'nvlink': 'Defective-only target; U11 modification and ROM check bypass needed; bring-up untested',
    'compute': 'PES and ROP_L2 must accompany GPC/TPC; native SM counts and FMA speed are die/driver dependent',
    'ecc': 'No ECC mapping or burn provided; a failed whole-block match does not prove absence of FF backing; separate ROM/InfoROM claims are unvalidated here',
    'restore': 'Additional records consume permanent OTP space; not physical fuse reversal',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class PublicDecodeGap(ValueError):
    """A record whose treatment is not established by this public-only model."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def word(value):
    require(not isinstance(value, bool), 'Boolean is not a register value')
    value = int(value, 0) if isinstance(value, str) else value
    require(isinstance(value, int) and 0 <= value <= 0xffffffff, 'Invalid 32-bit value')
    require(value & 0xffff0000 != 0xbadf0000, 'PRI error response in selected evidence')
    require(value != 0xffffffff, 'Ambiguous all-ones value in selected evidence')
    return value


def canonical_name(name):
    if name in ('IFF_RECORD', 'NV_FUSE_IFF_RECORD'):
        return 'NV_FUSE_IFF_RECORD'
    if name in ('CRC_STATUS', 'crc_status'):
        return 'NV_FUSE_CRC_STATUS'
    if name.startswith('OPT_TPC_DISABLE_GPC'):
        return 'NV_FUSE_OPT_TPC_GPC'+name[len('OPT_TPC_DISABLE_GPC'):]+'_DISABLE'
    return 'NV_FUSE_'+name if name.startswith('OPT_') else name


def allowed_registers():
    result = {option_name(field): spec[3] for field, spec in FIELDS.items()}
    result.update({defect_name(field): offset for field, offset in DEFECT_REGISTERS.items()})
    result.update({'NV_FUSE_IFF_RECORD': IFF_RECORD_OFFSET,
                   'NV_FUSE_OPT_DISABLE_GEN3_SPEED': 0x820250,
                   'NV_FUSE_CRC_STATUS': 0x820070,
                   'NV_FUSE_OPT_PCIE_DEVIDA': 0x8204d8,
                   'NV_FUSE_OPT_PCIE_DEVIDB': 0x82056c})
    return result


def normalize_options(sample):
    require(isinstance(sample, dict), 'Option sample must be an object')
    result = {}
    allowed = allowed_registers()
    for name, value in sample.items():
        name = canonical_name(name)
        if name in allowed:
            value = word(value)
            require(name not in result or result[name] == value, f'Conflicting aliases: {name}')
            result[name] = value
    return result


def normalize_bdf(value):
    require(isinstance(value, str) and re.fullmatch(
        r'(?:[0-9a-fA-F]{4}|0000[0-9a-fA-F]{4}):[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]', value),
        'Invalid capture BDF')
    return value[-12:].lower()


def valid_uuid(capture):
    target = capture.get('target', {})
    value = capture.get('gpu_uuid', target.get('gpu_uuid'))
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'GPU-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})', value)
    if not match:
        return None
    digits = match[1].replace('-', '').lower()
    if len(digits) != 32 or set(digits) in ({'0'}, {'f'}):
        return None  # Redacted/sentinel UUIDs are not card identity evidence.
    return value.lower()


def check_capture_errors(capture):
    require(isinstance(capture, dict), 'Capture must be a JSON object')
    require(not capture.get('error') and not capture.get('read_errors'), 'Capture reports read errors')
    require(not any(capture.get('read_issues', [])), 'Capture reports unreliable register reads')
    for flag in ('complete', 'ok', 'options_match', 'samples_match', 'raw_match', 'controller_idle'):
        if flag in capture:
            require(type(capture[flag]) is bool and capture[flag], f'Capture reports invalid/false {flag}')
    if 'status' in capture:
        require(str(capture['status']).upper() == 'COMPLETE', 'Capture status is not COMPLETE')
    if 'fusectrl' in capture:
        require((word(capture['fusectrl']) >> 16) & 31 == 4, 'Captured fuse controller is not IDLE')


def raw_word(value):
    require(not isinstance(value, bool), 'Boolean is not a physical row value')
    value = int(value, 0) if isinstance(value, str) else value
    require(type(value) is int and 0 <= value <= 0xffffffff, 'Invalid raw word')
    return value


def row_entries(entries):
    require(isinstance(entries, list), 'rows/ff_rows must be row/raw objects, not an unindexed word array')
    result = {}
    for entry in entries:
        require(isinstance(entry, dict), 'Each row entry needs explicit row and raw fields')
        row = entry.get('row')
        require(type(row) is int and 0 <= row < 512, 'Invalid physical row index')
        require(row not in result, f'Duplicate physical row {row}')
        require(not entry.get('error') and entry.get('raw') is not None, f'Physical row {row} failed to read')
        result[row] = raw_word(entry['raw'])
    return result


def read_evidence(path):
    data = Path(path).read_bytes()
    capture = json.loads(data)
    check_capture_errors(capture)
    bdf = normalize_bdf(capture.get('bdf', capture.get('target', {}).get('bdf')))
    require(not ('rows' in capture and 'ff_rows' in capture), 'Ambiguous rows and ff_rows keys')
    raw_formats = [key for key in ('raw_rows', 'rows', 'ff_rows') if capture.get(key)]
    require(len(raw_formats) <= 1, 'Ambiguous physical-row schemas')
    require(sum(key in capture for key in ('samples', 'options', 'shadow')) == 1,
            'Ambiguous option schemas: provide exactly one of samples, options or shadow')
    samples = capture.get('samples', capture.get('options'))
    options_repeated = False
    if samples is not None:
        require(isinstance(samples, list) and len(samples) == 2, 'Need two option/status passes')
        normalized = [normalize_options(sample) for sample in samples]
        require(normalized[0] == normalized[1], 'Selected public option passes disagree')
        opts, options_repeated = normalized[0], True
    else:
        require('shadow' in capture, 'Unknown capture schema: need samples/options or reference toolkit shadow')
        opts = normalize_options(capture['shadow'])
        if 'crc_status' in capture:
            crc = word(capture['crc_status'])
            require('NV_FUSE_CRC_STATUS' not in opts or opts['NV_FUSE_CRC_STATUS'] == crc,
                    'Conflicting CRC observations')
            opts['NV_FUSE_CRC_STATUS'] = crc
    require(opts.get('NV_FUSE_CRC_STATUS') == 0x55, 'Need a capture with clean published CRC status')
    pci_device = capture.get('pci_device')
    if pci_device is not None:
        require(word(pci_device) == 0x20c2, 'Need a normal CMP 170HX capture')
    else:
        require(opts.get('NV_FUSE_OPT_PCIE_DEVIDA') == 0x20c2,
                'No CMP 170HX PCI identity or published DEVIDA evidence')
    rows, rows_repeated = None, False
    if raw_formats:
        key = raw_formats[0]
        if key == 'raw_rows':
            raw = capture[key]
            require(len(raw) == 2 and all(isinstance(p, list) and len(p) == 512 for p in raw),
                    'Need two complete raw_rows passes')
            passes = [[raw_word(value) for value in p] for p in raw]
            require(passes[0] == passes[1], 'Raw passes disagree')
            rows, rows_repeated = dict(enumerate(passes[0])), True
        else:
            rows = row_entries(capture[key])
    return {'bdf': bdf, 'opts': opts, 'rows': rows,
            'options_repeated': options_repeated, 'rows_repeated': rows_repeated,
            'uuid': valid_uuid(capture), 'sha256': hashlib.sha256(data).hexdigest(),
            'schema': raw_formats[0] if raw_formats else 'options-only'}


def option_name(field):
    return 'NV_FUSE_OPT_PCIE_MAGIC_BITS_D' if field == 'GEN4_DISABLE' else 'NV_FUSE_OPT_'+field


def defect_name(field):
    return 'NV_FUSE_OPT_'+field.replace('_DISABLE', '_DEFECTIVE')


def public_spec():
    return {
        'sources': {'ff_locations': BLOG, 'register_offsets': OPTIONS_SOURCE,
                    'controller_status': CORE_SOURCE},
        'boundary_register': {'name': 'NV_FUSE_IFF_RECORD', 'offset': IFF_RECORD_OFFSET,
                              'start_bits': [0, 8], 'last_bits': [16, 24],
                              'provenance': 'User-supplied GA100 FF burn map, 2026-11-17',
                              'meaning': 'current writable IFF execution range; not immutable geometry'},
        'routes': list(ROUTES),
        'record_format': {'type_bit': FF_TYPE_BIT, 'iff_type_mask': IFF_TYPE_MASK,
                          'ff_chain_mask': FF_CHAIN_MASK,
                          'boundary': 'first observed type-bit-5 record; zeros do not establish IFF start'},
        'fields': {name: {'chain': chain, 'first_bit': bit, 'width': width,
                          'option': option_name(name), 'option_offset': hex(offset),
                          **(GEN4_REGISTER_BIT if name == 'GEN4_DISABLE' else {}),
                          **({'defect_option': defect_name(name),
                              'defect_offset': hex(DEFECT_REGISTERS[name])}
                             if name in DEFECT_REGISTERS else {})}
                   for name, (chain, bit, width, offset) in FIELDS.items()},
        'experimental_features': {'pcie-gen3-pair': GEN3_PAIR,
                                  'pcie-gen4-completion': list(MAGIC_COMPLETION),
                                  'a100-device-id': {'target': '0x20b5', 'rom_required': True},
                                  'sys-pipe': {'field': 'SYS_PIPE_DISABLE', 'claim': 'MIG enumeration only; ECC/NVDEC not established'}},
        'conversion_findings': CONVERSION_FINDINGS,
        'unresolved': {'DISABLE_GEN3_SPEED': 'Individual bit unresolved; local pcie-gen3-pair clears candidates 1 and 9 together.'},
    }


def load_capture(path, repeat=None, defects=None):
    evidence = read_evidence(path)
    sources = {'baseline': evidence['sha256']}
    missing = []
    if repeat is not None:
        require(Path(path).resolve() != Path(repeat).resolve(), '--repeat must name a separate capture file')
        other = read_evidence(repeat)
        require(other['bdf'] == evidence['bdf'], 'Repeat capture BDF mismatch')
        require(other['opts'] == evidence['opts'], 'Repeat public option observations disagree')
        require(other['rows'] == evidence['rows'], 'Repeat physical rows disagree')
        if evidence['uuid'] or other['uuid']:
            require(evidence['uuid'] == other['uuid'], 'Repeat card UUID mismatch')
        evidence['options_repeated'] = True
        evidence['rows_repeated'] = evidence['rows'] is not None
        sources['repeat'] = other['sha256']
    if not evidence['options_repeated']:
        missing.append('second matching option capture; pass --repeat')
    if evidence['rows'] is None:
        missing.append('physical FF row observations')
    elif not evidence['rows_repeated']:
        missing.append('second matching physical-row capture; pass --repeat')
    target_origins = {name: 'baseline' for name in evidence['opts']}
    association = None
    if defects is not None:
        raw = Path(defects).read_bytes()
        snapshot = json.loads(raw)
        check_capture_errors(snapshot)
        require(snapshot.get('complete') is True and type(snapshot.get('matching_passes')) is int
                and snapshot['matching_passes'] == 2,
                'Defect snapshot must be complete with two matching passes')
        require(normalize_bdf(snapshot.get('target', {}).get('bdf')) == evidence['bdf'],
                'Defect snapshot BDF mismatch')
        entries = snapshot.get('registers')
        require(isinstance(entries, list), 'Defect snapshot requires a registers array')
        selected, allowed = {}, allowed_registers()
        for entry in entries:
            require(isinstance(entry, dict), 'Invalid defect register entry')
            name = canonical_name(entry.get('name', ''))
            if name not in allowed:
                continue
            require(not entry.get('error') and entry.get('second_read_matches') is True,
                    f'Defect snapshot register did not pass repeatability checks: {name}')
            require(raw_word(entry.get('offset')) == allowed[name], f'Defect register address mismatch: {name}')
            value = word(entry.get('value'))
            if 'second_value' in entry:
                require(word(entry['second_value']) == value, f'Defect register passes disagree: {name}')
            require(name not in selected, f'Duplicate defect register entry: {name}')
            selected[name] = value
        for name in evidence['opts'].keys() & selected.keys():
            require(evidence['opts'][name] == selected[name], f'Defect snapshot conflicts with baseline: {name}')
        uuid = valid_uuid(snapshot)
        association = 'matching UUID' if uuid is not None and uuid == evidence['uuid'] else 'BDF only; unverified'
        if uuid is not None and evidence['uuid'] is not None:
            require(uuid == evidence['uuid'], 'Defect snapshot belongs to another card UUID')
        for field in DEFECT_REGISTERS:
            name = defect_name(field)
            if name in selected and name not in evidence['opts']:
                evidence['opts'][name] = selected[name]
                target_origins[name] = 'defect-snapshot'
        sources['defects'] = hashlib.sha256(raw).hexdigest()
    evidence.update(sources=sources, missing=missing, target_origins=target_origins,
                    defect_association=association)
    return evidence


def decode(rows):
    if isinstance(rows, list):
        rows = dict(enumerate(rows))
    blocks, last = {}, 221
    for row in range(222, 512):
        if row not in rows:
            return blocks, last+1, None
        value = raw_word(rows[row])
        require(value & 0xffff0000 != 0xbadf0000, f'PRI error response in FF row {row}')
        if value == 0xffffffff:
            raise PublicDecodeGap(f'Unsupported all-ones FF row {row}; no invalidation rule assumed')
        if value & IFF_TYPE_MASK:
            return blocks, last+1, row  # Nothing after the first IFF marker is interpreted as FF.
        if value == 0:
            continue
        chain, block = value & FF_CHAIN_MASK, (value >> 6) & 1023
        if chain in (0, 31):
            raise PublicDecodeGap(f'Unclassified chain-{chain} record in row {row}; public-only model will not guess')
        blocks[chain, block] = value >> 16
        last = row
    return blocks, last+1, None


def get_field(blocks, field):
    chain, start, width, _ = FIELDS[field]
    return sum(((blocks.get((chain, bit//16), 0) >> (bit % 16)) & 1) << (bit-start)
               for bit in range(start, start+width))


def edit_field(blocks, field, value):
    chain, start, width, _ = FIELDS[field]
    require(0 <= value < 1 << width, 'Target does not fit public field width')
    for i in range(width):
        bit = start+i
        key, mask = (chain, bit//16), 1 << (bit % 16)
        blocks[key] = (blocks.get(key, 0) & ~mask) | (((value >> i) & 1) * mask)


def register_effects(edits, opts, replayed_blocks=None):
    """Model only the explicitly mapped register bit; preserve every other bit."""
    effects = []
    for edit in edits:
        if edit['field'] != 'GEN4_DISABLE' or edit['old'] is None:
            continue
        before = opts[option_name('GEN4_DISABLE')]
        value = (get_field(replayed_blocks, 'GEN4_DISABLE') if replayed_blocks is not None
                 else edit['target'])
        if value is None:
            continue
        mask = GEN4_REGISTER_BIT['register_mask']
        after = (before & ~mask) | (value << GEN4_REGISTER_BIT['register_bit'])
        require((before ^ after) & ~mask == 0, 'Gen4 register effect changed an unrelated bit')
        require((after >> 25) & 1 == value, 'Gen4 register bit model mismatch')
        if replayed_blocks is not None:
            require(value == edit['target'], 'Replayed Gen4 FF bit differs from the requested register bit')
        effects.append({**GEN4_REGISTER_BIT, 'before': before, 'after': after,
                        'bit_before': (before >> 25) & 1, 'bit_after': value,
                        'unrelated_register_bits_preserved': True,
                        'model_only': True, 'working_gen4_established': False})
    magic_name = 'NV_FUSE_OPT_PCIE_MAGIC_BITS_D'
    current = effects[-1]['after'] if effects else opts.get(magic_name)
    for edit in edits:
        if edit['field'] not in {spec['field'] for spec in MAGIC_COMPLETION} or current is None or edit['target'] is None:
            continue
        if replayed_blocks is not None:
            require(replayed_blocks.get((edit['ff_chain'], edit['ff_block'])) & edit['ff_mask'] == 0,
                    'MAGIC_D completion replay did not clear the group')
        after = current & ~edit['register_mask']
        effects.append({'field': edit['field'], 'register_offset': 0x820520,
                        'register_mask': edit['register_mask'], 'before': current, 'after': after,
                        'unrelated_register_bits_preserved': True, 'model_only': True,
                        'mapping_scope': 'reference die; not verified on this card',
                        'working_gen4_established': False})
        current = after
    return effects


def iff_boundary_evidence(opts, rows, start, boundary, missing, repeated):
    value = opts.get('NV_FUSE_IFF_RECORD')
    result = {'source': 'raw type bit 5 and repeated IFF_RECORD',
              'type_bit': FF_TYPE_BIT, 'type_mask': IFF_TYPE_MASK,
              'first_iff_row': boundary,
              'first_iff_word': rows[boundary] if boundary is not None else None,
              'last_occupied_ff_row': start-1 if start is not None else None,
              'iff_record_raw': value, 'iff_start': None, 'iff_last': None,
              'iff_register_checked': False, 'eight_zero_rule_assumed': False,
              'hardware_geometry_established': False}
    if value is None:
        missing.append('two matching NV_FUSE_IFF_RECORD observations (0x820050); recapture required')
        return result
    first, last = value & 0x1ff, (value >> 16) & 0x1ff
    require(222 <= first <= last < 512, 'Invalid or inactive IFF_RECORD range')
    result.update(iff_start=first, iff_last=last)
    if boundary is not None:
        require(first == boundary, 'IFF_RECORD START disagrees with the first raw bit-5 marker')
        result['iff_register_checked'] = bool(repeated)
    return result


def compute_dependencies(blocks, opts, known=True):
    checks = []
    for field in ('PES_DISABLE', 'ROP_L2_DISABLE'):
        target = opts.get(defect_name(field))
        observed = opts.get(option_name(field))
        actual = get_field(blocks, field) if known and observed is not None else None
        checks.append({'field': field, 'required_defect_mask': target,
                       'logical_mask': actual,
                       'satisfied': actual is not None and target is not None and actual == target})
    return checks


def proof_preview(old, records, reserved):
    """Unallocated encoding candidates from untouched, declared FF blocks only."""
    touched = {(record['chain'], record['block']) for record in records}
    declared = {(chain, bit//16) for chain, start, width, _ in FIELDS.values()
                for bit in range(start, start+width)}
    declared.update((spec['ff_chain'], spec['ff_block']) for spec in MAGIC_COMPLETION)
    candidates = []
    if reserved:
        for chain, block in sorted((declared & set(old)) - touched):
            data = old[chain, block]
            replayed = dict(old)
            replayed[chain, block] = data
            require(replayed == old, 'Proof candidate would change the logical baseline')
            candidates.append({'chain': chain, 'block': block, 'data': data,
                               'word': (data << 16) | (block << 6) | chain,
                               'row': None, 'logical_no_op_verified': True,
                               'physical_no_op_established': False})
    return {'rows_reserved': reserved, 'records_generated': False,
            'candidates': candidates, 'selection': 'none; independent human review required',
            'note': 'Encoding candidates only, with no physical row or execution order. Fresh capture and cold-boot verification are required; no automatic proof burns.'}


def checkpoint_preview(old, records, opts):
    """Prefix replay is informative, never a resumable or executable stage plan."""
    blocks, result = dict(old), []
    for index, record in enumerate(records, 1):
        blocks[record['chain'], record['block']] = record['new_block']
        result.append({'index': index, 'after_row': record['row'],
                       'logical_records_applied': index,
                       'compute_dependencies': compute_dependencies(blocks, opts),
                       'bootability_established': False, 'cold_boot_verified': False,
                       'fresh_capture_required_before_followup': True,
                       'note': 'Intermediate masks may be incomplete; not a bootable-stage or execution manifest.'})
    return result


def make_plan(baseline, groups, repeat=None, defects=None, route='cmp', proof_rows=0):
    evidence = load_capture(baseline, repeat, defects)
    opts, rows = evidence['opts'], evidence['rows']
    groups = sorted(set(groups))
    require(groups and all(group in GROUPS for group in groups), 'Invalid feature selection')
    require(route in ROUTES, 'Invalid conversion route')
    require(type(proof_rows) is int and 0 <= proof_rows <= 512, 'Invalid proof-row reservation')
    require('a100-device-id' not in groups or route in ('a100', 'empirical'),
            'Device-ID changes require explicit --route a100 or --route empirical')
    require('pcie-gen4-completion' not in groups or route == 'empirical',
            'Extra MAGIC_D clearing requires --route empirical; it is not a universal A100 conversion requirement')
    old, start, boundary = {}, None, None
    missing = list(evidence['missing'])
    if rows is not None:
        try:
            old, start, boundary = decode(rows)
        except PublicDecodeGap as exc:
            missing.append(str(exc))
    new, edits = dict(old), []
    if rows is not None and boundary is None:
        missing.append('contiguous FF observations from row 222 through the first IFF marker; no boundary inferred')
    boundary_evidence = iff_boundary_evidence(opts, rows, start, boundary, missing, evidence['options_repeated'])
    seen_fields = set()
    for group in groups:
        for field in GROUPS[group]:
            if field in seen_fields:
                continue
            seen_fields.add(field)
            name = option_name(field)
            width = FIELDS[field][2]
            before = opts.get(name)
            if before is not None and field == 'GEN4_DISABLE':
                before = (before >> 25) & 1
            device_id = field in GROUPS['a100-device-id']
            target = 0x20b5 if device_id else (0 if field in GATE_FIELDS else opts.get(defect_name(field)))
            if (field not in GATE_FIELDS and evidence['target_origins'].get(defect_name(field)) == 'defect-snapshot'
                    and evidence['defect_association'] != 'matching UUID'):
                missing.append('defect snapshot/card association: matching BDF alone does not identify a card')
            if before is None:
                missing.append(name)
            else:
                require(before < 1 << width, f'Published field exceeds its known width: {field}')
                if rows is not None and boundary is not None:
                    require(get_field(old, field) == before, f'Published FF mapping does not match this capture: {field}')
            if target is None:
                missing.append(defect_name(field))
            else:
                require(target < 1 << width, f'Published defect mask exceeds its known width: {field}')
            if before is not None and target is not None:
                if device_id:
                    require(before == 0x20c2, 'Device-ID conversion requires original CMP 20c2 shadows')
                else:
                    require(target & ~before == 0, f'Defects are not contained in disable mask: {field}')
                edit_field(new, field, target)
            edits.append({'field': field, 'old': before, 'target': target,
                          **(GEN4_REGISTER_BIT if field == 'GEN4_DISABLE' else {}),
                          'target_source': ('reference toolkit A100 conversion target' if device_id else
                                            'public gate policy' if field in GATE_FIELDS else
                                            evidence['target_origins'].get(defect_name(field))),
                          'evidence_complete': before is not None and target is not None})
    if 'pcie-gen3-pair' in groups:
        key = (2, 39)
        before = old.get(key) if boundary is not None else None
        shadow = opts.get('NV_FUSE_OPT_DISABLE_GEN3_SPEED')
        if before is None:
            missing.append('explicit chain-2 block-39 record and observed IFF boundary')
        if shadow is None:
            missing.append('NV_FUSE_OPT_DISABLE_GEN3_SPEED')
        else:
            require(shadow in (0, 1), 'Invalid Gen3 speed-disable shadow')
        if before is not None:
            target = before & ~GEN3_PAIR['ff_mask']
            new[key] = target
        else:
            target = None
        edits.append({**GEN3_PAIR, 'old': before, 'target': target,
                      'observed_speed_disable': shadow,
                      'predicted_speed_disable': None,
                      'target_source': 'explicit reference toolkit experimental pair policy',
                      'evidence_complete': before is not None and shadow is not None})
    if 'pcie-gen4-completion' in groups:
        magic = opts.get('NV_FUSE_OPT_PCIE_MAGIC_BITS_D')
        for spec in MAGIC_COMPLETION:
            key = (spec['ff_chain'], spec['ff_block'])
            before = old.get(key) if boundary is not None else None
            if before is None:
                missing.append('explicit original FF block for '+spec['field'])
            if magic is None:
                missing.append('NV_FUSE_OPT_PCIE_MAGIC_BITS_D')
            if before is not None and magic is not None:
                ff_group, register_group = before & spec['ff_mask'], magic & spec['register_mask']
                require((ff_group == spec['ff_mask'] and register_group == spec['register_mask'])
                        or (ff_group == 0 and register_group == 0),
                        'Capture does not match empirical MAGIC_D group: '+spec['field'])
            target = before & ~spec['ff_mask'] if before is not None else None
            if target is not None:
                new[key] = new.get(key, before) & ~spec['ff_mask']
            edits.append({**spec, 'old': before, 'target': target,
                          'target_source': CONVERSION_FINDINGS['source'],
                          'mapping_scope': 'reference die; group mapping only',
                          'per_card_volatile_validation_required': True,
                          'hardware_mapping_verified_on_this_card': False,
                          'evidence_complete': before is not None and magic is not None})
    dependencies = compute_dependencies(new, opts, known=boundary is not None) if 'compute' in groups else []
    if 'compute' in groups:
        for field in ('PES_DISABLE', 'ROP_L2_DISABLE'):
            observed, target = opts.get(option_name(field)), opts.get(defect_name(field))
            if observed is None or target is None:
                missing.append('compute dependency evidence: '+field+' and its defect mask')
            elif boundary is not None:
                width = FIELDS[field][2]
                require(0 <= observed < 1 << width and 0 <= target < 1 << width,
                        'Compute dependency mask exceeds field width: '+field)
                require(get_field(old, field) == observed, 'Compute dependency FF/shadow mismatch: '+field)
                if get_field(new, field) != target:
                    missing.append('compute dependency '+field+' must reach its captured defect mask; include memory with compute')
    records = []
    space_budget = {'functional_rows': 0, 'proof_rows_reserved': proof_rows,
                    'restore_rows_reserved': 0, 'software_reserved_rows': SPARE_FF_ROWS,
                    'observed_trailing_blank_rows': boundary-start if boundary is not None else None,
                    'required_rows': None, 'remaining_after_all_reservations': None}
    if not missing:
        changed = [(key, data) for key, data in sorted(new.items()) if data != old.get(key, 0)]
        # Reserve 16 rows as a software planning policy, not a hardware specification.
        required = 2*len(changed) + proof_rows + SPARE_FF_ROWS
        space_budget.update(functional_rows=len(changed), restore_rows_reserved=len(changed),
                            required_rows=required,
                            remaining_after_all_reservations=boundary-start-required)
        require(start+required <= boundary,
                'Insufficient observed trailing FF space for functional, proof, restore and spare reservations')
        for i, ((chain, block), data) in enumerate(changed):
            require((chain, block) in old, 'Touched block has no explicit original record; default bits are unverified')
            row = start+i
            require(rows[row] == 0, 'Proposed append row is occupied')
            records.append({'row': row, 'chain': chain, 'block': block,
                            'old_block': old[chain, block], 'new_block': data,
                            'word': (data << 16) | (block << 6) | chain})
    for edit in edits:
        if edit['field'] in {spec['field'] for spec in MAGIC_COMPLETION} and edit['target'] is not None:
            edit['target'] = new[edit['ff_chain'], edit['ff_block']]
    validate_records(records, rows, start, boundary, 'pcie-gen3-pair' in groups)
    result = {
        'schema': 'ga100-public-ff-plan-v2',
        'public_sources_only': not bool(EXPERIMENTAL_FEATURES.intersection(groups)),
        'conversion_findings': CONVERSION_FINDINGS,
        **({'experimental_evidence': {feature: public_spec()['experimental_features'][feature]
                                   for feature in sorted(EXPERIMENTAL_FEATURES.intersection(groups))}}
           if EXPERIMENTAL_FEATURES.intersection(groups) else {}),
        'sources': public_spec()['sources'], 'bdf': evidence['bdf'], 'features': groups,
        'route': route, 'space_budget': space_budget, 'dependency_checks': dependencies,
        'cold_boot_checkpoints': checkpoint_preview(old, records, opts),
        'proof_preview': proof_preview(old, records, proof_rows) if not missing else
                         {'rows_reserved': proof_rows, 'records_generated': False, 'candidates': [],
                          'note': 'Incomplete evidence; proof encodings withheld.'},
        'restoration_preview': {'rows_reserved': len(records), 'rows_allocated': False,
                                'blocks': [{'chain': r['chain'], 'block': r['block'], 'original_data': r['old_block']} for r in records],
                                'note': 'Original values only. Fresh post-change evidence is required before allocating restoration rows; no physical undo or automatic restore.'},
        'input_files_sha256': evidence['sources'], 'public_spec_sha256': digest(public_spec()),
        'specimen': {'capture_bdf': evidence['bdf'], 'gpu_uuid': evidence['uuid'],
                     'physical_observation_sha256': digest(sorted(rows.items())) if rows is not None else None,
                     'ff_observation_sha256': digest([(r, rows[r]) for r in range(222, boundary)])
                                                if boundary is not None else None,
                     'note': 'Captured-data fingerprints, not an independently verified silicon identity.'},
        'capture_evidence': {'format': evidence['schema'],
                             'option_repeats_match': evidence['options_repeated'],
                             'row_repeats_match': evidence['rows_repeated'],
                             'observed_row_count': len(rows) if rows is not None else 0,
                             'defect_snapshot_association': evidence['defect_association']},
        'status': 'incomplete' if missing else 'logical-plan-complete',
        'missing_evidence': sorted(set(missing)), 'field_edits': edits, 'records': records,
        'register_effects': register_effects(edits, opts),
        'iff_boundary': boundary,
        'ff_boundary_evidence': {**boundary_evidence,
            'observed_trailing_blank_rows': boundary-start if boundary is not None else None,
            'remaining_blank_rows_after_plan': boundary-start-len(records) if boundary is not None else None,
            'software_reserved_rows': SPARE_FF_ROWS},
        'physical_defect_aliases_verified': False,
        'programming_eligibility_established': False,
        'limitations': ['SYS_PIPE changes do not establish ECC, NVDEC or media-engine enablement.',
                        'Cold-boot checkpoints are logical previews only; no successful boot or stage is established.',
                        'Public defect option values are not independently checked against physical aliases.',
                        'Gen3 block-39 ambiguity is unresolved; clearing MAGIC_D[25] alone does not establish working Gen4.',
                        'MAGIC_D completion uses one-die empirical groups; per-card volatile validation is required before hardware use.',
                        'Device-ID conversion requires a matching ROM; NVLink and ECC operation are not established.',
                        'Logical FF replay only; no controller, voltage, GPIO or programming-supply model.',
                        'Public planning schema; incompatible with the separate legacy burner manifest.'],
    }
    result['plan_id'] = digest(result)
    return result


def validate_records(records, rows, start, boundary, allow_gen3_pair=False):
    seen = set()
    for record in records:
        row, chain, block = record['row'], record['chain'], record['block']
        data, encoded = record['new_block'], record['word']
        require(type(encoded) is int and 0 <= encoded <= 0xffffffff, 'Invalid 32-bit FF encoding')
        require(encoded & IFF_TYPE_MASK == 0, 'IFF-type word is not an FF replacement record')
        require(type(chain) is int and chain in (1, 2) and type(block) is int and 0 <= block < 1024
                and type(data) is int and 0 <= data < 65536, 'Invalid FF record fields')
        require(encoded == (data << 16) | (block << 6) | chain, 'FF encoding does not match its fields')
        require(type(row) is int and start is not None and boundary is not None
                and start <= row < boundary and row not in seen, 'Invalid or duplicate append row')
        require(rows is not None and rows.get(row) == 0, 'Append row was not observed blank')
        if chain == 2 and block == 39:
            require(allow_gen3_pair, 'Gen3 block 39 requires explicit pcie-gen3-pair selection')
            old = record['old_block']
            require(type(old) is int and 0 <= old < 65536
                    and data == old & ~GEN3_PAIR['ff_mask'],
                    'Gen3 pair edit must preserve all bits outside 1 and 9')
        seen.add(row)


def simulate(baseline, plan, repeat=None, defects=None):
    require(plan == make_plan(baseline, plan['features'], repeat, defects,
                              route=plan.get('route', 'cmp'),
                              proof_rows=plan.get('space_budget', {}).get('proof_rows_reserved', 0)),
            'Plan differs from regeneration; check card and all input files')
    require(plan['status'] == 'logical-plan-complete', 'Missing evidence prevents FF replay simulation')
    evidence = load_capture(baseline, repeat, defects)
    before = evidence['rows']
    after = dict(before)
    for record in plan['records']:
        require(after[record['row']] == 0, 'Simulation would overwrite an occupied row')
        after[record['row']] |= record['word']
    blocks, _, _ = decode(after)
    for edit in plan['field_edits']:
        actual = (blocks.get((edit['ff_chain'], edit['ff_block'])) if 'ff_mask' in edit
                  else get_field(blocks, edit['field']))
        require(actual == edit['target'], 'Simulated field replay mismatch')
    return {'simulation_only': True, 'model': 'public FF record replay', 'plan_id': plan['plan_id'],
            'records_applied': len(plan['records']),
            'changed_rows': [i for i in sorted(before) if before[i] != after[i]],
            'route': plan['route'], 'space_budget': plan['space_budget'],
            'cold_boot_checkpoints': checkpoint_preview(decode(before)[0], plan['records'], evidence['opts']),
            'cold_boot_verified': False, 'working_features_verified': False,
            'public_fields': {edit['field']: get_field(blocks, edit['field']) for edit in plan['field_edits']
                              if 'ff_mask' not in edit},
            'experimental_fields': {edit['field']: {**edit, 'replayed_block': blocks.get((edit['ff_chain'], edit['ff_block']))}
                                    for edit in plan['field_edits'] if 'ff_mask' in edit},
            'register_effects': register_effects(plan['field_edits'], evidence['opts'], blocks),
            'programming_eligibility_established': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('public', help='Show only the public field specification and its sources')
    p = sub.add_parser('plan', help='Plan from a full baseline, or report missing public-capture evidence')
    p.add_argument('--baseline', required=True)
    p.add_argument('--features', nargs='+', choices=GROUPS, default=['memory', 'compute', 'pcie-gen3-pair'],
                   help='Default: memory compute pcie-gen3-pair; explicit selections replace the defaults')
    p.add_argument('--route', choices=ROUTES, default='cmp', help='Intended path; extra MAGIC_D clearing requires empirical')
    p.add_argument('--proof-rows', type=int, default=0, help='Reserve space for separately reviewed proof records; generates no proof writes')
    p.add_argument('--output', help='New JSON file; defaults to stdout; incomplete plans exit 2 and contain no records')
    p.add_argument('--repeat', help='Separate matching reference toolkit dump; never invents a second pass')
    p.add_argument('--defects', help='Complete, repeated public register snapshot from the same card')
    p = sub.add_parser('simulate', help='Replay complete public-only plans without hardware access')
    p.add_argument('--baseline', required=True)
    p.add_argument('--plan', required=True)
    p.add_argument('--repeat', help='Same repeat-capture input used when planning')
    p.add_argument('--defects', help='Same defect-snapshot input used when planning')
    args = parser.parse_args(argv)
    if args.command == 'public':
        result = public_spec()
    elif args.command == 'plan':
        result = make_plan(args.baseline, args.features, args.repeat, args.defects, args.route, args.proof_rows)
    else:
        result = simulate(args.baseline, json.loads(Path(args.plan).read_text()), args.repeat, args.defects)
    if getattr(args, 'output', None):
        with open(args.output, 'x') as out:
            json.dump(result, out, indent=2)
            out.write('\n')
    else:
        print(json.dumps(result, indent=2))
    return 2 if result.get('status') == 'incomplete' else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, IndexError, KeyboardInterrupt) as exc:
        print(f'STOP: {exc}', file=sys.stderr)
        raise SystemExit(1)
