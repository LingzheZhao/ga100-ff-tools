#!/usr/bin/env python3
"""Offline reference toolkit source/plan audit. Never opens a GPU or invokes live tools."""
import argparse
import ast
import contextlib
import io
import re
import hashlib
import json
from pathlib import Path
import types


def require(ok, message):
    if not ok:
        raise ValueError(message)


def number(value):
    return int(value, 0) if isinstance(value, str) else value


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def functions(path, names):
    """Compile only named pure functions; exclude imports, entrypoints and MMIO classes."""
    tree = ast.parse(path.read_text())
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    require({n.name for n in nodes} == set(names), 'Missing reference functions')
    ns = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)
    return ns


def literal(path, name):
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('Missing constant '+name)


def canonical(name):
    if name.startswith('OPT_TPC_DISABLE_GPC'):
        return 'TPC_GPC'+name[len('OPT_TPC_DISABLE_GPC'):]+'_DISABLE'
    return name[4:] if name.startswith('OPT_') else name


def decode(rows):
    blocks, last = {}, 221
    for row in range(222, len(rows)):
        value = rows[row]
        require(value >> 16 != 0xbadf, 'PRI response in FF range')
        if value & 32:
            return blocks, last+1, row
        if not value:
            continue
        chain, block, data = value & 31, (value >> 6) & 1023, value >> 16
        require(chain not in (0, 31), 'Unclassified reserved-chain record in evidence')
        # Other chains are retained opaquely and checked unchanged, never targeted.
        blocks[chain, block] = data
        last = row
    raise ValueError('No observed IFF boundary')


def extract(blocks, chain, lo, hi):
    return sum(((blocks.get((chain, bit//16), 0) >> (bit % 16)) & 1) << (bit-lo)
               for bit in range(lo, hi+1))


def set_bits(blocks, chain, lo, hi, value):
    for bit in range(lo, hi+1):
        key, mask = (chain, bit//16), 1 << (bit % 16)
        blocks[key] = (blocks.get(key, 0) & ~mask) | (((value >> (bit-lo)) & 1) * mask)


def audit(tools, plans, dumps, card_names=None):
    root = Path(__file__).resolve().parent
    # Our planner supplies declared mappings only; no planning/decoding functions are reused.
    ns = {'__name__': 'declarations_only'}
    exec(compile((root/'ffplan.py3').read_text(), str(root/'ffplan.py3'), 'exec'), ns)
    fields = ns['FIELDS']
    reference = literal(tools/'ff_dump.py', 'FF_OPTIONS')
    reference += [('OPT_TPC_DISABLE_GPC'+str(i), 1, 187+8*i, 194+8*i) for i in range(8)]
    for name, chain, lo, hi in reference:
        field = canonical(name)
        if field == 'SYS_PIPE_DISABLE':
            continue  # Preserved, not edited by our policies.
        require(tuple(fields[field][:3]) == (chain, lo, hi-lo+1), 'FF mapping mismatch: '+field)
    for name, chain, lo, hi, defect in literal(tools/'ff_derive.py', 'TARGETS'):
        require(tuple(fields[canonical(name)][:3]) == (chain, lo, hi-lo+1), 'derive mapping mismatch')
    for name, chain, lo, hi, _ in literal(tools/'ff_derive_pes.py', 'TARGETS'):
        require(tuple(fields[canonical(name)][:3]) == (chain, lo, hi-lo+1), 'PES mapping mismatch')
    pcie = literal(tools/'ff_derive_pcie.py', 'CHAIN')
    require(pcie == 2, 'Reference PCIe chain changed')
    # The mask expressions are evaluated as integer arithmetic only, never executing the script.
    tree = ast.parse((tools/'ff_derive_pcie.py').read_text())
    target = next(n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'TARGETS' for t in n.targets))
    allowed = (ast.Expression, ast.List, ast.Tuple, ast.Constant, ast.BinOp, ast.BitOr, ast.LShift, ast.Load)
    require(all(isinstance(n, allowed) for n in ast.walk(ast.Expression(target))), 'Unexpected PCIe mask expression')
    masks = eval(compile(ast.Expression(target), '<integer masks>', 'eval'), {'__builtins__': {}})
    require({b: mask for b, mask, _ in masks} == {39: 0x0202, 47: 8, 49: 0xc0}, 'PCIe mask mismatch')
    capture_ns = {'__name__': 'capture_declarations_only'}
    capture_path = root/'capture.py3'
    if not capture_path.exists():
        capture_path = root.parent/'public/capture.py3'
    exec(compile(capture_path.read_text(), str(capture_path), 'exec'), capture_ns)
    for field, (_, _, _, offset) in fields.items():
        require(capture_ns['REGISTERS'][ns['option_name'](field)] == offset, 'Capture offset mismatch '+field)
    for field, offset in ns['DEFECT_REGISTERS'].items():
        require(capture_ns['REGISTERS'][ns['defect_name'](field)] == offset, 'Capture defect offset mismatch '+field)
    for ours, theirs in [('FUSECTRL','FUSECTRL'),('FUSEADDR','FUSEADDR'),('FUSEDATA','FUSERDATA'),
                        ('FUSEDEBUG','DEBUGCTRL'),('CRC_STATUS','CRC_STATUS')]:
        require(capture_ns[ours] == literal(tools/'ff_burn.py', theirs), 'Controller offset mismatch '+ours)
    # Source-only reproductions: pure functions with synthetic data and fake reads.
    pure = functions(tools/'ff_derive.py', ['extract', 'derive', 'verify'])
    pure['TARGETS'] = literal(tools/'ff_derive.py', 'TARGETS')
    pure['TARGETS'] += [('OPT_TPC_DISABLE_GPC'+str(i), 1, 187+8*i, 194+8*i, 'OPT_TPC_GPC'+str(i)+'_DEFECTIVE') for i in range(8)]
    original, _, records, changes = pure['derive']({'chains': {'1': {'19': '0xffff'}}}, {})
    require(pure['verify'](original, records, {}) and any(c['target'] == '0x0' for c in changes), 'Expected missing-defect behavior changed')
    dump = functions(tools/'ff_dump.py', ['decode_record', 'build_chains'])
    bad = dump['decode_record'](0xbadf510c)
    require(bad['chain'] == 12 and bad['iff'] == 0, 'PRI decode reproduction changed')
    sample = [dump['decode_record'](0x10000 | (5 << 6) | 1), dump['decode_record'](0x20), dump['decode_record'](0x20000 | (5 << 6) | 1)]
    require(dump['build_chains'](sample)[1][5] == 2, 'IFF skip reproduction changed')
    scan = functions(tools/'ff_magic_derive.py', ['scan'])
    scan.update(FF_START=222, FF_END=226)
    fake = {222: 0, 223: None, 224: 0x20, 225: (0x59 << 16) | (47 << 6) | 2, 226: 0}
    scan['read_row'] = lambda bar, row: fake[row]
    eff, latest, blanks = scan['scan'](None, (47 << 6) | 2)
    require(eff == 0x59 and latest == 225 and blanks[0] < latest, 'Scan reproduction changed')
    final = functions(tools/'final_check.py', ['main'])
    def unavailable(*args):
        raise OSError('synthetic BAR unavailable')
    parser = types.SimpleNamespace(add_argument=lambda *a, **k: None,
                                   parse_args=lambda: types.SimpleNamespace(bdf='0000:41:00.0'))
    final.update(argparse=types.SimpleNamespace(ArgumentParser=lambda: parser),
                 sys=types.SimpleNamespace(platform='linux'), re=re,
                 os=types.SimpleNamespace(open=unavailable, O_RDONLY=0),
                 sh=lambda cmd: '', sm_count=lambda: (None, None))
    with contextlib.redirect_stdout(io.StringIO()):
        require(final['main']() == 0, 'Final-check unavailable-data false success changed')
    checks = ['capture/planner option, defect and controller offsets agree',
              'final_check returns success with BAR, runtime and dmesg unavailable reproduced',
              'FF field ranges agree', 'PCIe masks agree', 'missing-defect false verification reproduced',
              'PRI response decoded as record reproduced', 'FF replay beyond IFF reproduced',
              'MAGIC scan skips failures/IFF and chooses earlier blank reproduced']
    cards = []
    if card_names is None:
        card_names = sorted(path.name[:-len('-plan.json')] for path in plans.glob('*-plan.json'))
    require(card_names and len(set(card_names)) == len(card_names), 'Need unique card names and matching plan files')
    for card in card_names:
        baseline = dumps/(card+'-raw.json')
        capture = json.loads(baseline.read_text())
        require(capture['options'][0] == capture['options'][1], card+': option repeat mismatch')
        require(capture['raw_rows'][0] == capture['raw_rows'][1], card+': physical repeat mismatch')
        opts = {n: number(v) for n, v in capture['options'][0].items()}
        require(opts['NV_FUSE_CRC_STATUS'] == 0x55, card+': CRC mismatch')
        rows = [number(v) for v in capture['raw_rows'][0]]
        require(len(rows) == 512, card+': incomplete array')
        before, start, boundary = decode(rows)
        plan = json.loads((plans/(card+'-plan.json')).read_text())
        require(plan['bdf'] == capture['bdf'], card+': BDF mismatch')
        require(plan['input_files_sha256']['baseline'] == sha(baseline), card+': baseline hash mismatch')
        payload = {k: v for k, v in plan.items() if k != 'plan_id'}
        calculated = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        require(plan['plan_id'] == calculated, card+': plan hash mismatch')
        require(set(plan['features']) == {'memory','compute','pcie-gen3-pair','pcie-known','pcie-gen4-completion','nvlink','a100-device-id'}, card+': scope mismatch')
        desired = dict(before)
        expected_fields = {}
        for field, (chain, lo, width, _) in fields.items():
            observed = (opts['NV_FUSE_OPT_PCIE_MAGIC_BITS_D'] >> 25) & 1 if field == 'GEN4_DISABLE' else opts['NV_FUSE_OPT_'+field]
            require(extract(before, chain, lo, lo+width-1) == observed, card+': FF/shadow mismatch '+field)
            if field in ('PCIE_DEVIDA', 'PCIE_DEVIDB'):
                require(observed == 0x20c2, card+': unexpected source ID')
                target = 0x20b5
            elif field in ('GEN4_DISABLE', 'PCIE_BOOT_GEN23_DISABLE', 'PCIE_BOOT_GEN3_DISABLE'):
                target = 0
            else:
                target = opts['NV_FUSE_OPT_'+field.replace('_DISABLE', '_DEFECTIVE')]
                require(target & ~observed == 0, card+': defective units not retained')
            expected_fields[field] = target
            set_bits(desired, chain, lo, lo+width-1, target)
        desired[2,39] &= ~0x0202
        desired[2,46] &= ~0x2000
        desired[2,47] &= ~0x0051
        expected_changes = {key: value for key, value in desired.items() if before.get(key, 0) != value}
        got, used = {}, set()
        after_rows = rows[:]
        for record in plan['records']:
            row, chain, block, data, encoded = (record[k] for k in ('row','chain','block','new_block','word'))
            require(start <= row < boundary and rows[row] == 0 and row not in used, card+': invalid append row')
            require(encoded == (data << 16) | (block << 6) | chain and not encoded & 32, card+': encoding mismatch')
            require(record['old_block'] == before[chain,block], card+': original block mismatch')
            require((chain,block) not in got, card+': duplicate block')
            got[chain,block] = data;used.add(row);after_rows[row] = encoded
        require(got == expected_changes, card+': final blocks differ from independent policy')
        require(sorted(used) == list(range(start, start+len(got))), card+': unexpected allocation')
        require(boundary-start-len(got) >= 16, card+': reserve mismatch')
        replayed, _, replay_boundary = decode(after_rows)
        require(all(replayed.get(k, 0) == desired.get(k, 0) for k in set(replayed) | set(desired))
                and replay_boundary == boundary, card+': independent replay mismatch')
        for field, target in expected_fields.items():
            chain, lo, width, _ = fields[field]
            require(extract(replayed, chain, lo, lo+width-1) == target, card+': target mismatch '+field)
        require((before[1,23] ^ replayed[1,23]) & ~7 == 0, card+': SYS_PIPE/adjacent NVLink bits modified')
        sim = json.loads((plans/(card+'-simulation.json')).read_text())
        require(sim['plan_id'] == plan['plan_id'] and sim['records_applied'] == len(got), card+': saved simulation mismatch')
        require(sim['public_fields'] == expected_fields, card+': saved field results mismatch')
        magic = opts['NV_FUSE_OPT_PCIE_MAGIC_BITS_D'] & ~sum(1 << bit for bit in (19,22,25,26,28))
        require(sim['register_effects'][-1]['after'] == magic, card+': MAGIC model mismatch')
        cards.append({'card': card, 'bdf': plan['bdf'], 'passed': True, 'records': len(got),
                      'row_range': [min(used), max(used)], 'modeled_magic_d': hex(magic),
                      'plan_id': plan['plan_id'], 'baseline_sha256': sha(baseline)})
    inventory = []
    for path in sorted(tools.glob('*.py')):
        ast.parse(path.read_text())
        inventory.append({'file':path.name, 'sha256':sha(path), 'syntax_valid':True})
    return {'offline_only':True, 'hardware_validated':False, 'source_directory':str(tools),
            'planner_sha256':sha(root/'ffplan.py3'), 'source_inventory':inventory,
            'reference_fixture_sha256':sha(tools/'ff.json'), 'cross_checks':checks, 'cards':cards,
            'limits':['Source agreement is not independent proof of silicon mapping.',
                      'Gen3 individual bit and MAGIC group permutation remain unresolved.',
                      'This audit does not execute any live MMIO, glitch, burn, reset, probe, flash or CUDA tool.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--plans', type=Path, required=True)
    parser.add_argument('--dumps', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cards', nargs='+', help='Filename prefixes; default: discover PREFIX-plan.json')
    args = parser.parse_args()
    result = audit(args.tools, args.plans, args.dumps, args.cards)
    with args.output.open('x') as f:
        json.dump(result, f, indent=2);f.write('\n')
    print(json.dumps({'cards_passed':len(result['cards']), 'tools_reviewed':len(result['source_inventory']), 'output':str(args.output)}))


if __name__ == '__main__':
    main()
