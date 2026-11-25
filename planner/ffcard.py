#!/usr/bin/env python3
"""Per-card CMP 170HX FF plans: derive, in-window check, post-burn verify. OFFLINE.

Works only on JSON written by ff_dump.py and read_defects.py. Opens no device,
writes no register and burns nothing; ff_burn.py stays the only write path.

Hardened validation guarantees:
  - Requires controller_idle is True and crc_status == "0x55" in derive, check,
    and verify (missing or null controller_idle is REFUSED, never treated as OK).
  - Requires GFW ready (low byte == 0xFF) whenever gfw/gfw_ready is present.
  - Binds die_id / die_id_hash (rows 8-15) into plans and enforces exact match
    in check and verify whenever present in the baseline.
  - Re-validates every record's encoding, IFF bit=0, row bounds, duplicate rows,
    and forbidden device-ID blocks when loading plans.
  - In verify: requires all SHADOWED expected fields and unchanged DEVID shadows
    to exist and match (no silent skipping of missing shadows); when --defects
    is supplied, requires all expected defect masks to exist and match.

Exit status: 0 OK, 1 check failed or input refused.
"""
import argparse
import hashlib
import json
import os
import sys

FF_START, FF_END = 222, 487
FORBIDDEN = {(2, 37), (2, 38)}  # PCIE_DEVIDA/B: never burn

SM_HBM = [("OPT_FBIO_DISABLE", 1, 83, 106, "OPT_FBIO_DEFECTIVE"),
          ("OPT_FBPA_DISABLE", 1, 107, 130, "OPT_FBPA_DEFECTIVE"),
          ("OPT_GPC_DISABLE", 1, 131, 138, "OPT_GPC_DEFECTIVE"),
          ("OPT_PES_DISABLE", 1, 251, 274, "OPT_PES_DEFECTIVE"),
          ("OPT_FBP_DISABLE", 1, 307, 318, "OPT_FBP_DEFECTIVE"),
          ("OPT_ROP_L2_DISABLE", 1, 319, 342, "OPT_ROP_L2_DEFECTIVE")] + \
         [("OPT_TPC_DISABLE_GPC%d" % i, 1, 187 + 8 * i, 194 + 8 * i,
           "OPT_TPC_GPC%d_DEFECTIVE" % i) for i in range(8)]
NVLINK = [("OPT_NVLINK_DISABLE", 1, 368, 370, "OPT_NVLINK_DEFECTIVE")]
UNCHANGED = [("OPT_SYS_PIPE_DISABLE", 1, 372, 379), ("OPT_PCIE_DEVIDA", 2, 593, 608),
             ("OPT_PCIE_DEVIDB", 2, 609, 624)]
UNCHANGED_SHADOWED = ["OPT_PCIE_DEVIDA", "OPT_PCIE_DEVIDB"]
# PCIe: (chain, block, expected old, new, note). Proven on four dies;
# applied only when the block holds the expected old value.
PCIE = [(2, 39, 0x0782, 0x0580, "DISABLE_GEN3_SPEED (bit1+bit9)"),
        (2, 49, 0x00E4, 0x0024, "BOOT_GEN23 + BOOT_GEN3 disable"),
        (2, 47, 0x0059, 0x0000, "PCIE_MAGIC_BITS_D bits 25,22,26,28 (Gen4)"),
        (2, 46, 0xA000, 0x8000, "PCIE_MAGIC_BITS_D bit19 (Gen4)")]
PCIE_REGISTERS = {"DISABLE_GEN3_SPEED 0x820250": "0x00000000",
                  "BOOT_GEN23_DISABLE 0x82057C": "0x00000000",
                  "BOOT_GEN3_DISABLE 0x820580": "0x00000000",
                  "PCIE_MAGIC_BITS_D 0x820520": "0x00200000"}
# ff_dump.py shadow names checked by verify (the rest live in read_defects.py).
SHADOWED = ["OPT_GPC_DISABLE", "OPT_FBP_DISABLE", "OPT_FBPA_DISABLE", "OPT_FBIO_DISABLE"] + \
           ["OPT_TPC_DISABLE_GPC%d" % i for i in range(8)]
DEFECT_FILE_SHADOWS = {"OPT_PES_DISABLE", "OPT_ROP_L2_DISABLE"}
PLAN_ORDER = ["0_noop", "sm_hbm", "pcie", "nvlink"]


class Refused(Exception):
    pass


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_dump_health(dump):
    problems = []
    if dump.get("crc_status") != "0x55":
        problems.append("CRC %r (want '0x55')" % (dump.get("crc_status"),))
    if dump.get("controller_idle") is not True:
        problems.append("controller_idle %r (must be explicitly True)" % (dump.get("controller_idle"),))
    if "gfw_ready" in dump and dump["gfw_ready"] is not True:
        problems.append("gfw_ready %r (must be True)" % (dump.get("gfw_ready"),))
    if "gfw" in dump:
        try:
            gfw_val = int(dump["gfw"], 16)
        except (TypeError, ValueError):
            problems.append("invalid gfw value %r" % (dump.get("gfw"),))
        else:
            if (gfw_val & 0xFF) != 0xFF:
                problems.append("GFW 0x%08X low byte != 0xFF" % gfw_val)
    return problems


def load_rows(dump):
    """{row: word} for every row the dump read; refuses on read errors."""
    if dump.get("read_errors"):
        raise Refused("dump has read errors at rows %s" % dump["read_errors"])
    rows = {}
    for r in dump.get("rows", []):
        if r.get("raw") is None:
            raise Refused("row %d was not read" % r["row"])
        rows[r["row"]] = int(r["raw"], 16)
    for b in dump.get("blank_rows", []):  # hand-transcribed dumps list only used rows
        rows.setdefault(b, 0)
    missing = [i for i in range(FF_START, FF_END + 1) if i not in rows]
    if missing:
        raise Refused("dump does not cover rows %d-%d" % (missing[0], missing[-1]))
    return rows


def occupancy(rows):
    """Last occupied row; the used rows must be contiguous from FF_START."""
    used = [i for i in range(FF_START, FF_END + 1) if rows[i]]
    if not used:
        raise Refused("no FF records in the dump")
    last = used[-1]
    holes = [i for i in range(FF_START, last) if not rows[i]]
    if holes:
        raise Refused("blank rows inside the used range: %s" % holes)
    iff = [i for i in used if rows[i] & 0x20]
    if iff:
        raise Refused("rows with the IFF bit (bit 5) set: %s" % iff)
    return last


def fingerprint(rows, last):
    s = ",".join("0x%08X" % rows[i] for i in range(FF_START, last + 1))
    return hashlib.sha256(s.encode()).hexdigest()[:16]


def replay(rows, upto=FF_END):
    """Chains from the records in row order; the last record per block wins."""
    chains = {}
    for i in range(FF_START, upto + 1):
        v = rows[i]
        if v:
            chains.setdefault(v & 0x1F, {})[(v >> 6) & 0x3FF] = v >> 16
    return chains


def extract(chains, c, lo, hi):
    v = 0
    for b, d in chains.get(c, {}).items():
        v |= d << (16 * b)
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)


def field_plan(chains, fields, defects):
    """Records that set each field to its defect mask, merged per block."""
    desired = {c: dict(bm) for c, bm in chains.items()}
    allowed = {}
    for _, c, lo, hi, dname in fields:
        target = defects[dname]
        for p in range(lo, hi + 1):
            b, bit = divmod(p, 16)
            allowed.setdefault((c, b), 0)
            allowed[(c, b)] |= 1 << bit
            d = desired.setdefault(c, {})
            d[b] = (d.get(b, 0) & ~(1 << bit)) | (((target >> (p - lo)) & 1) << bit)
    out = []
    for c in sorted(desired):
        for b in sorted(desired[c]):
            old, new = chains.get(c, {}).get(b, 0), desired[c][b]
            if new != old:
                assert (old ^ new) & ~allowed[(c, b)] == 0, "bit outside a field"
                out.append((c, b, old, new))
    return out


def record(c, b, old, new, note=None):
    assert (c, b) not in FORBIDDEN, "device-ID block"
    r = {"chain": c, "block": b, "old_data": "0x%04X" % old, "new_data": "0x%04X" % new,
         "encoded": "0x%08X" % ((new << 16) | (b << 6) | c)}
    if note:
        r["note"] = note
    if new & ~old:
        r["sets_bits"] = "0x%04X" % (new & ~old)
    return r


def load_defects(path, required_names=None):
    doc = load_json(path)
    regs = {r["name"]: int(r["value"], 16) for r in doc["registers"]}
    need = required_names if required_names is not None else [f[4] for f in SM_HBM + NVLINK]
    missing = [n for n in need if n not in regs]
    if missing:  # never default an unknown defect mask to zero
        raise Refused("defects file lacks %s" % ", ".join(missing))
    return regs, doc


def derive(args):
    dump = load_json(args.dump)
    health_probs = check_dump_health(dump)
    if health_probs:
        raise Refused("stock dump unhealthy: %s" % "; ".join(health_probs))
    rows = load_rows(dump)
    last = occupancy(rows)
    chains = replay(rows)
    if "chains" in dump:
        listed = {int(c): {int(b): int(d, 16) for b, d in bm.items()}
                  for c, bm in dump["chains"].items()}
        if listed != chains:
            raise Refused("rows do not replay to the dump's chains")
    # Cross-check shadow registers if present on stock cold dump.
    if isinstance(dump.get("shadow"), dict):
        field_map = {f[0]: f for f in SM_HBM}
        for name in SHADOWED:
            if name in dump["shadow"]:
                _, c, lo, hi, _ = field_map[name]
                replayed = extract(chains, c, lo, hi)
                sh_val = int(dump["shadow"][name], 16)
                if replayed != sh_val:
                    raise Refused("stock dump mismatch: %s replayed 0x%X != shadow 0x%X"
                                  % (name, replayed, sh_val))
    defects, defects_doc = load_defects(args.defects)
    if dump.get("bdf") and defects_doc.get("bdf") and dump["bdf"] != defects_doc["bdf"]:
        raise Refused("BDF mismatch between dump (%s) and defects (%s)"
                      % (dump["bdf"], defects_doc["bdf"]))
    fp = fingerprint(rows, last)
    baseline = {"last_row": last, "fingerprint": fp}
    if "die_id_hash" in dump:
        baseline["die_id_hash"] = dump["die_id_hash"]
    if "die_id" in dump:
        baseline["die_id"] = dump["die_id"]
    print("%s: rows %d-%d used, fingerprint %s%s" % (
        args.card, FF_START, last, fp,
        ("  die_id_hash %s" % baseline["die_id_hash"]) if "die_id_hash" in baseline else "",
    ))

    plans = {}
    if "noop" in args.plans:
        plans["0_noop"] = {"mode": "noop", "records": [
            record(1, 7, chains[1][7], chains[1][7], "mechanism test, value unchanged")]}
    if "sm_hbm" in args.plans:
        plans["sm_hbm"] = {"mode": "sm_hbm",
                           "records": [record(*r) for r in field_plan(chains, SM_HBM, defects)],
                           "expect_fields": {f[0]: "0x%X" % defects[f[4]] for f in SM_HBM}}
    if "pcie" in args.plans:
        wrong = ["block %d is 0x%04X, not 0x%04X" % (b, chains[c].get(b, 0), old)
                 for c, b, old, _, _ in PCIE if chains[c].get(b, 0) != old]
        if wrong:
            print("SKIP pcie: %s (the proven values do not apply to this die)" % "; ".join(wrong))
        else:
            plans["pcie"] = {"mode": "pcie_gen3_gen4",
                             "records": [record(*p) for p in PCIE],
                             "expect_registers": PCIE_REGISTERS}
    if "nvlink" in args.plans:
        plans["nvlink"] = {"mode": "nvlink",
                           "records": [record(*r) for r in field_plan(chains, NVLINK, defects)],
                           "expect_fields": {f[0]: "0x%X" % defects[f[4]] for f in NVLINK}}

    # Assign rows in burn order and check the merged result.
    row = last + 1 + args.skip_rows
    merged = {c: dict(bm) for c, bm in chains.items()}
    for key in PLAN_ORDER:
        plan = plans.get(key)
        if plan is None:
            continue
        if not plan["records"]:
            print("SKIP %s: already at target, nothing to burn" % key)
            del plans[key]
            continue
        for r in plan["records"]:
            if row > FF_END:
                raise Refused("out of blank rows")
            r["row"] = row
            row += 1
            merged.setdefault(r["chain"], {})[r["block"]] = int(r["new_data"], 16)
        plan.update(card=args.card, order=PLAN_ORDER.index(key),
                    source_dump=os.path.basename(args.dump),
                    source_defects=os.path.basename(args.defects),
                    baseline=dict(baseline),
                    unchanged_fields={n: "0x%X" % extract(chains, c, lo, hi)
                                      for n, c, lo, hi in UNCHANGED})
    for name, c, lo, hi, dname in SM_HBM + NVLINK:
        sel = "sm_hbm" if (name, c, lo, hi, dname) in SM_HBM else "nvlink"
        if sel not in plans:
            continue
        got, want = extract(merged, c, lo, hi), defects[dname]
        print("  %-22s 0x%-8X -> 0x%-8X %s" % (name, extract(chains, c, lo, hi), got,
                                               "OK" if got == want else "FAIL want 0x%X" % want))
        assert got == want
    for name, c, lo, hi in UNCHANGED:
        assert extract(merged, c, lo, hi) == extract(chains, c, lo, hi)
        print("  %-22s 0x%X unchanged" % (name, extract(chains, c, lo, hi)))

    os.makedirs(args.out_dir, exist_ok=True)
    for key, plan in plans.items():
        name = "%s_plan_%s.json" % (args.card, key)
        path = os.path.join(args.out_dir, name)
        if os.path.exists(path) and not args.force:
            raise Refused("%s exists (use --force to replace)" % path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(plan, f, indent=2)
            f.write("\n")
        print("\n%s" % name)
        for i, r in enumerate(plan["records"]):
            print("  %-2d row %d = %s  chain %d block %-2d %s -> %s%s" % (
                i, r["row"], r["encoded"], r["chain"], r["block"], r["old_data"], r["new_data"],
                "  SETS %s" % r["sets_bits"] if "sets_bits" in r else ""))
    return 0


def validate_plan_records(plans):
    seen_rows = set()
    unchanged_sets = set()
    for path, plan in plans:
        recs = plan.get("records")
        if not isinstance(recs, list) or not recs:
            raise Refused("plan %s has no records" % path)
        unchanged_sets.add(json.dumps(plan.get("unchanged_fields"), sort_keys=True))
        for i, r in enumerate(recs):
            row = r.get("row")
            c = r.get("chain")
            b = r.get("block")
            if not isinstance(row, int) or not (FF_START <= row <= FF_END):
                raise Refused("plan %s record %d has invalid row %r" % (path, i, row))
            if row in seen_rows:
                raise Refused("duplicate target row %d across plans" % row)
            seen_rows.add(row)
            if (c, b) in FORBIDDEN:
                raise Refused("plan %s record %d targets forbidden device-ID block (%s, %s)"
                              % (path, i, c, b))
            try:
                enc = int(r["encoded"], 16)
                new_d = int(r["new_data"], 16)
            except (KeyError, TypeError, ValueError) as exc:
                raise Refused("plan %s record %d malformed: %s" % (path, i, exc)) from exc
            if enc & 0x20:
                raise Refused("plan %s record %d sets IFF bit (bit 5)" % (path, i))
            want_enc = (new_d << 16) | (b << 6) | c
            if enc != want_enc:
                raise Refused("plan %s record %d encoded 0x%08X != expected 0x%08X"
                              % (path, i, enc, want_enc))
    if len(unchanged_sets) != 1:
        raise Refused("plans disagree on unchanged_fields")


def load_plans(paths):
    plans = [(p, load_json(p)) for p in paths]
    bases = {json.dumps(pl.get("baseline"), sort_keys=True) for _, pl in plans}
    if len(bases) != 1 or not plans[0][1].get("baseline"):
        raise Refused("plans must come from one ffcard.py derive run (baseline differs or missing)")
    validate_plan_records(plans)
    plans.sort(key=lambda x: x[1]["records"][0]["row"])
    return plans, plans[0][1]["baseline"]


def compare(dump, plans, base):
    """Per-record state against the plans. Returns (rows, burned, pending, problems)."""
    problems = check_dump_health(dump)
    if "die_id_hash" in base:
        if dump.get("die_id_hash") != base["die_id_hash"]:
            problems.append("die_id_hash %r != plan baseline %r: NOT the planned card"
                            % (dump.get("die_id_hash"), base["die_id_hash"]))
    if "die_id" in base:
        if dump.get("die_id") != base["die_id"]:
            problems.append("die_id rows 8-15 differ from plan baseline: NOT the planned card")
    rows = load_rows(dump)
    fp = fingerprint(rows, base["last_row"])
    if fp != base["fingerprint"]:
        problems.append("rows %d-%d fingerprint %s, plan baseline %s: NOT the planned card/state"
                        % (FF_START, base["last_row"], fp, base["fingerprint"]))
        return rows, [], [], problems  # per-row comparison is meaningless on another card
    burned, pending, plan_rows = [], [], set()
    for path, plan in plans:
        for i, r in enumerate(plan["records"]):
            got, want = rows[r["row"]], int(r["encoded"], 16)
            plan_rows.add(r["row"])
            item = (os.path.basename(path), i, r["row"], r["encoded"])
            if got == want:
                if pending:
                    problems.append("row %d burned after an unburned row %d" % (r["row"], pending[0][2]))
                burned.append(item)
            elif got == 0:
                pending.append(item)
            else:
                problems.append("row %d = 0x%08X, plan %s" % (r["row"], got, r["encoded"]))
    stray = [i for i in range(base["last_row"] + 1, FF_END + 1) if rows[i] and i not in plan_rows]
    if stray:
        problems.append("rows outside the plans are written: %s" % stray)
    return rows, burned, pending, problems


def check(args):
    plans, base = load_plans(args.plans)
    rows, burned, pending, problems = compare(load_json(args.dump), plans, base)
    print("baseline rows %d-%d: %s" % (FF_START, base["last_row"],
                                       "match" if not any("fingerprint" in p for p in problems) else "DIFFER"))
    print("burned %d, pending %d" % (len(burned), len(pending)))
    for p in problems:
        print("STOP: %s" % p)
    if problems:
        return 1
    if pending:
        name, i, row, enc = pending[0]
        print("OK to burn. Next: --plan %s --index %d  (row %d = %s)" % (name, i, row, enc))
    else:
        print("All records already burned; nothing to do in this window.")
    return 0


def verify(args):
    plans, base = load_plans(args.plans)
    dump = load_json(args.dump)
    rows, burned, pending, problems = compare(dump, plans, base)
    for name, i, row, enc in pending:
        problems.append("not burned: %s index %d (row %d = %s)" % (name, i, row, enc))
    chains = replay(rows)
    fields = {f[0]: f for f in SM_HBM + NVLINK}
    shadow_dict = dump.get("shadow")
    if not isinstance(shadow_dict, dict):
        problems.append("dump is missing required 'shadow' register dict")
        shadow_dict = {}

    for _, plan in plans:
        for name, want in plan.get("expect_fields", {}).items():
            _, c, lo, hi, _ = fields[name]
            got = extract(chains, c, lo, hi)
            print("  %-22s 0x%-8X %s" % (name, got, "OK" if got == int(want, 16) else "FAIL want " + want))
            if got != int(want, 16):
                problems.append("%s = 0x%X, want %s" % (name, got, want))
            if name in SHADOWED:
                shadow = shadow_dict.get(name)
                if shadow is None:
                    problems.append("missing required shadow register %s" % name)
                elif int(shadow, 16) != int(want, 16):
                    problems.append("shadow %s = %s, want %s" % (name, shadow, want))

    for name, c, lo, hi in UNCHANGED:
        want = int(plans[0][1]["unchanged_fields"][name], 16)
        got = extract(chains, c, lo, hi)
        print("  %-22s 0x%-8X %s" % (name, got, "unchanged" if got == want else "CHANGED"))
        if got != want:
            problems.append("%s changed: 0x%X, was 0x%X" % (name, got, want))
        if name in UNCHANGED_SHADOWED:
            sh = shadow_dict.get(name)
            if sh is None:
                problems.append("missing required unchanged shadow register %s" % name)
            elif int(sh, 16) != want:
                problems.append("shadow %s = %s, want unchanged 0x%X" % (name, sh, want))

    if args.defects:
        need_defects = [
            fields[name][4]
            for _, plan in plans
            for name in plan.get("expect_fields", {})
        ]
        regs, _ = load_defects(args.defects, required_names=need_defects)
        for _, plan in plans:
            for name, want in plan.get("expect_fields", {}).items():
                dname = fields[name][4]
                if regs[dname] != int(want, 16):
                    problems.append("defect mask %s now 0x%X, planned for %s" % (dname, regs[dname], want))
                if name in DEFECT_FILE_SHADOWS and name in regs:
                    if regs[name] != int(want, 16):
                        problems.append("shadow %s in defects file = 0x%X, want %s"
                                        % (name, regs[name], want))

    status = {k: v for k, v in shadow_dict.items()
              if k.startswith("STATUS_OPT_TPC_GPC") and int(v, 16)}
    if status:
        print("note: %s nonzero (runtime TPC mask, not a fuse; may cost SMs)" %
              ", ".join("%s=%s" % kv for kv in sorted(status.items())))
    for _, plan in plans:
        if plan.get("expect_registers"):
            print("PCIe registers are not in the dump: run pcie_state.py (targets %s)" %
                  ", ".join("%s=%s" % kv for kv in plan["expect_registers"].items()))

    last_plan_row = max(
        (r["row"] for _, pl in plans for r in pl["records"]),
        default=base["last_row"],
    )
    nxt = next((i for i in range(max(base["last_row"], last_plan_row) + 1, FF_END + 1)
                if not rows[i]), None)
    print("first blank row: %s" % nxt)
    for p in problems:
        print("FAIL: %s" % p)
    print("VERIFY %s" % ("FAIL" if problems else "PASS"))
    return 1 if problems else 0


def fingerprint_cmd(args):
    rows = load_rows(load_json(args.dump))
    last = occupancy(rows)
    print("rows %d-%d fingerprint %s  (row %d = 0x%08X)" % (
        FF_START, last, fingerprint(rows, last), last, rows[last]))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("derive", help="write per-card burn plans")
    p.add_argument("--card", required=True, help="name used in the plan file names")
    p.add_argument("--dump", required=True, help="stock ff_dump.py JSON")
    p.add_argument("--defects", required=True, help="stock read_defects.py JSON")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--plans", nargs="+", default=["noop", "sm_hbm", "pcie", "nvlink"],
                   choices=["noop", "sm_hbm", "pcie", "nvlink"])
    p.add_argument("--skip-rows", type=int, default=0,
                   help="blank rows to leave before the first record (default 0)")
    p.add_argument("--force", action="store_true", help="replace existing plan files")
    p.set_defaults(fn=derive)
    p = sub.add_parser("check", help="in-window check before burning")
    p.add_argument("--dump", required=True, help="fresh ff_dump.py JSON from this window")
    p.add_argument("plans", nargs="+")
    p.set_defaults(fn=check)
    p = sub.add_parser("verify", help="post-burn verification after a cold boot")
    p.add_argument("--dump", required=True, help="ff_dump.py JSON after the cold boot")
    p.add_argument("--defects", help="read_defects.py JSON after the cold boot")
    p.add_argument("plans", nargs="+")
    p.set_defaults(fn=verify)
    p = sub.add_parser("fingerprint", help="hash of the occupied rows")
    p.add_argument("--dump", required=True)
    p.set_defaults(fn=fingerprint_cmd)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Refused as e:
        print("REFUSED: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
