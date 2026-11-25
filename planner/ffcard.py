#!/usr/bin/env python3
"""Per-card CMP 170HX FF plans: derive, in-window check, post-burn verify. OFFLINE.

Works only on JSON written by ff_dump.py (with embedded same-card defects and
die-ID). Opens no device, writes no register, and burns nothing; ff_burn.py
stays the only write path.

Hardened safety & stage-isolation guarantees:
  - Strict stage separation:
      * derive: requires cold stock dump (DSOV == 1), die_id_hash, matching
        shadows, and same-card bound defects (embedded in dump or --defects
        carrying matching die_id_hash).
      * check:  requires active glitch-window dump (DSOV == 0) and matching
        die_id_hash + baseline fingerprint. Rejects cold dumps.
      * verify: requires post-burn cold-boot dump (DSOV == 1), matching
        die_id_hash, canonical fields derived from plan mode (never blindly
        trusting plan expect_fields), final same-card defects, and ALL shadow
        registers including OPT_PES_DISABLE and OPT_ROP_L2_DISABLE.
  - Rejects shadow_only dumps, missing/false controller_idle, CRC != 0x55,
    DEBUGCTRL.RWL != 0, missing/poisoned/0xFFFFFFFF/unready GFW, duplicate row
    indices, or incomplete rows (never synthesizes missing rows from blank_rows).
  - Bit-level protection for OPT_PCIE_DEVIDA/B including bit 0 of block (2, 39).
  - Embeds plan_set and prior_records into every plan plus <card>_manifest.json
    so check/verify/ff_burn refuse missing earlier plans.

Exit status: 0 OK, 1 check failed or input refused.
"""
import argparse
import glob
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.bar0 import (  # noqa: E402
    GA100_BOOT0,
    RWL_BIT,
    die_id_hash as compute_die_id_hash,
    gfw_ready,
    is_poisoned,
)

FF_START, FF_END = 222, 487
FORBIDDEN = {(2, 37), (2, 38)}  # PCIE_DEVIDA/B primary blocks: never burn
# Bit-level protection covering ALL bits of OPT_PCIE_DEVIDA (2:593..608) and
# OPT_PCIE_DEVIDB (2:609..624), including bit 0 of block (2, 39) (bit 624).
FORBIDDEN_BITS = {
    (2, 37): 0xFFFE,
    (2, 38): 0xFFFF,
    (2, 39): 0x0001,
}

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
SHADOWED = ["OPT_GPC_DISABLE", "OPT_FBP_DISABLE", "OPT_FBPA_DISABLE", "OPT_FBIO_DISABLE"] + \
           ["OPT_TPC_DISABLE_GPC%d" % i for i in range(8)]
DEFECT_FILE_SHADOWS = ("OPT_PES_DISABLE", "OPT_ROP_L2_DISABLE")
PLAN_ORDER = ["0_noop", "sm_hbm", "pcie", "nvlink"]
KNOWN_MODES = {"noop", "sm_hbm", "pcie_gen3_gen4", "nvlink"}


class Refused(Exception):
    pass


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _parse_u32(val, label):
    if isinstance(val, int) and not isinstance(val, bool):
        n = val
    elif isinstance(val, str):
        try:
            n = int(val, 16)
        except ValueError as exc:
            raise Refused("invalid hex %s: %r" % (label, val)) from exc
    else:
        raise Refused("invalid %s: %r" % (label, val))
    if not (0 <= n <= 0xFFFFFFFF):
        raise Refused("out-of-range uint32 %s: 0x%X" % (label, n))
    return n


def canonical_fields_for_mode(mode):
    if mode == "sm_hbm":
        return [f[0] for f in SM_HBM]
    if mode == "nvlink":
        return [f[0] for f in NVLINK]
    if mode in ("noop", "pcie_gen3_gen4"):
        return []
    raise Refused("unknown plan mode %r" % (mode,))


def authorized_bit_masks_for_plans(plans):
    """Map (chain, block) -> bitmask of bits authorized to change by the given plans."""
    allowed = {}
    for _, plan in plans:
        mode = plan.get("mode")
        if mode == "noop":
            continue
        elif mode == "sm_hbm":
            for _, c, lo, hi, _ in SM_HBM:
                for p in range(lo, hi + 1):
                    b, bit = divmod(p, 16)
                    allowed[(c, b)] = allowed.get((c, b), 0) | (1 << bit)
        elif mode == "nvlink":
            for _, c, lo, hi, _ in NVLINK:
                for p in range(lo, hi + 1):
                    b, bit = divmod(p, 16)
                    allowed[(c, b)] = allowed.get((c, b), 0) | (1 << bit)
        elif mode == "pcie_gen3_gen4":
            for c, b, old, new, _ in PCIE:
                allowed[(c, b)] = allowed.get((c, b), 0) | (old ^ new)
        else:
            raise Refused("unknown plan mode %r" % (mode,))
    return allowed


def check_dump_health(dump, stage=None):
    """Validate dump health and strict stage isolation (derive / check / verify)."""
    problems = []
    if dump.get("shadow_only") is True:
        problems.append("shadow_only dump cannot be used for %s" % (stage or "planning"))
    if dump.get("crc_status") != "0x55":
        problems.append("CRC %r (want '0x55')" % (dump.get("crc_status"),))
    if dump.get("controller_idle") is not True:
        problems.append("controller_idle %r (must be explicitly True)" % (dump.get("controller_idle"),))
    if dump.get("gfw_ready") is not True:
        problems.append("gfw_ready %r (must be explicitly True)" % (dump.get("gfw_ready"),))
    if "gfw" not in dump:
        problems.append("missing required 'gfw' register reading")
    else:
        try:
            gfw_val = _parse_u32(dump["gfw"], "gfw")
        except Refused as exc:
            problems.append(str(exc))
        else:
            if not gfw_ready(gfw_val):
                problems.append("GFW 0x%08X not ready / dead / poisoned" % gfw_val)
    if "boot0" in dump:
        try:
            b0 = _parse_u32(dump["boot0"], "boot0")
        except Refused as exc:
            problems.append(str(exc))
        else:
            if b0 != GA100_BOOT0:
                problems.append("BOOT0 0x%08X != GA100 0x%08X" % (b0, GA100_BOOT0))

    ctrl = dump.get("control")
    if not isinstance(ctrl, dict):
        problems.append("missing required 'control' register snapshot (cannot verify DSOV / DEBUGCTRL)")
    else:
        for req_reg in ("DSOV", "DEBUGCTRL"):
            if req_reg not in ctrl:
                problems.append("control snapshot missing %s" % req_reg)
        if "DEBUGCTRL" in ctrl:
            try:
                dbg = _parse_u32(ctrl["DEBUGCTRL"], "control.DEBUGCTRL")
            except Refused as exc:
                problems.append(str(exc))
            else:
                if is_poisoned(dbg) or dbg == 0xFFFFFFFF:
                    problems.append("control.DEBUGCTRL poisoned/dead: 0x%08X" % dbg)
                elif (dbg & RWL_BIT) != 0:
                    problems.append("control.DEBUGCTRL.RWL != 0 (0x%08X; wrong fuse array)" % dbg)
        if "DSOV" in ctrl:
            try:
                dsov = _parse_u32(ctrl["DSOV"], "control.DSOV")
            except Refused as exc:
                problems.append(str(exc))
            else:
                if is_poisoned(dsov) or dsov == 0xFFFFFFFF:
                    problems.append("control.DSOV poisoned/dead: 0x%08X" % dsov)
                elif stage == "derive" and dsov != 1:
                    problems.append("derive requires cold stock dump (DSOV=1), got DSOV=0x%X" % dsov)
                elif stage == "check" and dsov != 0:
                    problems.append("check requires in-window dump (DSOV=0), got DSOV=0x%X (cold dump refused)" % dsov)
                elif stage == "verify" and dsov != 1:
                    problems.append("verify requires post-burn cold-boot dump (DSOV=1), got DSOV=0x%X" % dsov)

    # Die-ID integrity check whenever present (and required for derive/check/verify)
    if stage in ("derive", "check", "verify"):
        dh = dump.get("die_id_hash")
        if not isinstance(dh, str) or len(dh) != 16:
            problems.append("dump is missing valid 16-char 'die_id_hash' (required to bind card identity)")
        if "die_id" in dump:
            die_list = dump["die_id"]
            if not isinstance(die_list, list) or len(die_list) != 8:
                problems.append("dump 'die_id' must be 8 hex words (rows 8-15)")
            else:
                try:
                    vals = [_parse_u32(v, "die_id") for v in die_list]
                except Refused as exc:
                    problems.append(str(exc))
                else:
                    recomputed = compute_die_id_hash(vals)
                    if dh != recomputed:
                        problems.append("die_id_hash %r != sha256(die_id) %r" % (dh, recomputed))
    return problems


def load_rows(dump):
    """{row: word} for every row 222..487; refuses unread rows, duplicates, and read errors."""
    if dump.get("read_errors"):
        raise Refused("dump has read errors at rows %s" % dump["read_errors"])
    raw_rows = dump.get("rows")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise Refused("dump is missing explicit 'rows' list")
    rows = {}
    for entry in raw_rows:
        if not isinstance(entry, dict) or "row" not in entry:
            raise Refused("malformed row entry in dump: %r" % (entry,))
        rnum = entry["row"]
        if not isinstance(rnum, int) or isinstance(rnum, bool):
            raise Refused("invalid row number %r" % (rnum,))
        if rnum in rows:
            raise Refused("duplicate row %d in dump" % rnum)
        if entry.get("raw") is None:
            raise Refused("row %d was not read (raw is None)" % rnum)
        rows[rnum] = _parse_u32(entry["raw"], "row %d" % rnum)
    # NEVER backfill unread rows from blank_rows: every row 222..487 must be explicitly observed.
    missing = [i for i in range(FF_START, FF_END + 1) if i not in rows]
    if missing:
        raise Refused("dump is missing explicit row observations (first=%d, last=%d, count=%d)"
                      % (missing[0], missing[-1], len(missing)))
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
    """Chains from the records in physical row order; the last record per block wins."""
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
                if (old ^ new) & ~allowed.get((c, b), 0):
                    raise Refused("bit outside target field in block (%d, %d)" % (c, b))
                if (old ^ new) & FORBIDDEN_BITS.get((c, b), 0):
                    raise Refused("bit change touches forbidden device-ID bit in block (%d, %d)" % (c, b))
                out.append((c, b, old, new))
    return out


def record(c, b, old, new, note=None):
    if (c, b) in FORBIDDEN:
        raise Refused("forbidden device-ID block (%d, %d)" % (c, b))
    if (old ^ new) & FORBIDDEN_BITS.get((c, b), 0):
        raise Refused("record modifies forbidden device-ID bit in block (%d, %d)" % (c, b))
    r = {"chain": c, "block": b, "old_data": "0x%04X" % old, "new_data": "0x%04X" % new,
         "encoded": "0x%08X" % ((new << 16) | (b << 6) | c)}
    if note:
        r["note"] = note
    if new & ~old:
        r["sets_bits"] = "0x%04X" % (new & ~old)
    return r


def resolve_defects(dump, defects_path, required_names):
    """Resolve defect masks bound to the SAME die_id_hash as dump.

    Accepts either:
      1. Embedded dump['defects'] dict (captured in the same ff_dump.py session), or
      2. Separate --defects JSON that carries an explicit matching die_id_hash.
    Refuses any unbound defects JSON lacking die_id_hash (prevents A-card defects
    from ever mixing into a B-card plan even in the same PCI slot).
    """
    dump_dh = dump.get("die_id_hash")
    if defects_path:
        doc = load_json(defects_path)
        doc_dh = doc.get("die_id_hash")
        if not doc_dh or doc_dh != dump_dh:
            raise Refused(
                "defects file %s has die_id_hash=%r != dump die_id_hash=%r "
                "(unbound or wrong-card defects refused; use unified ff_dump.py capture)"
                % (defects_path, doc_dh, dump_dh)
            )
        if dump.get("bdf") and doc.get("bdf") and dump["bdf"] != doc["bdf"]:
            raise Refused("BDF mismatch between dump (%s) and defects (%s)"
                          % (dump["bdf"], doc["bdf"]))
        if isinstance(doc.get("defects"), dict):
            regs = {n: _parse_u32(v, "defects.%s" % n) for n, v in doc["defects"].items()}
        elif isinstance(doc.get("registers"), list):
            regs = {r["name"]: _parse_u32(r["value"], "defects.%s" % r["name"])
                    for r in doc["registers"]}
        else:
            raise Refused("defects file %s missing 'defects' or 'registers'" % defects_path)
        src_label = os.path.basename(defects_path)
    else:
        embedded = dump.get("defects")
        if not isinstance(embedded, dict):
            raise Refused(
                "dump lacks embedded 'defects' dict and no bound --defects file was supplied "
                "(re-capture with unified planner/ff_dump.py)"
            )
        regs = {n: _parse_u32(v, "dump.defects.%s" % n) for n, v in embedded.items()}
        src_label = "embedded_in_dump"

    for n, v in regs.items():
        if is_poisoned(v) or v == 0xFFFFFFFF:
            raise Refused("defect/shadow register %s is poisoned/dead: 0x%08X" % (n, v))
    missing = [n for n in required_names if n not in regs]
    if missing:
        raise Refused("defects data lacks required register(s): %s" % ", ".join(missing))
    return regs, src_label


def derive(args):
    if args.skip_rows < 0:
        raise Refused("--skip-rows must be >= 0, got %d" % args.skip_rows)
    dump = load_json(args.dump)
    health_probs = check_dump_health(dump, stage="derive")
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

    # Require shadow dict on stock cold dump and verify ALL shadowed fields + DEVIDA/B match!
    shadow_dict = dump.get("shadow")
    if not isinstance(shadow_dict, dict):
        raise Refused("stock dump is missing required 'shadow' register dict")
    field_map = {f[0]: f for f in SM_HBM}
    for name in SHADOWED:
        if name not in shadow_dict:
            raise Refused("stock dump is missing required shadow register %s" % name)
        _, c, lo, hi, _ = field_map[name]
        replayed = extract(chains, c, lo, hi)
        sh_val = _parse_u32(shadow_dict[name], "shadow.%s" % name)
        if replayed != sh_val:
            raise Refused("stock dump mismatch: %s replayed 0x%X != shadow 0x%X"
                          % (name, replayed, sh_val))
    unchanged_map = {u[0]: u for u in UNCHANGED}
    for name in UNCHANGED_SHADOWED:
        if name not in shadow_dict:
            raise Refused("stock dump is missing required unchanged shadow register %s" % name)
        _, c, lo, hi = unchanged_map[name]
        replayed = extract(chains, c, lo, hi)
        sh_val = _parse_u32(shadow_dict[name], "shadow.%s" % name)
        if replayed != sh_val:
            raise Refused("stock dump mismatch: %s replayed 0x%X != shadow 0x%X"
                          % (name, replayed, sh_val))

    # Only require defect masks for the plans actually selected!
    need_defects = []
    if "sm_hbm" in args.plans:
        need_defects.extend(f[4] for f in SM_HBM)
    if "nvlink" in args.plans:
        need_defects.extend(f[4] for f in NVLINK)
    defects, defects_src = ({}, None)
    if need_defects:
        defects, defects_src = resolve_defects(dump, args.defects, need_defects)
        for sh_name in DEFECT_FILE_SHADOWS:
            if sh_name in defects:
                _, c, lo, hi, _ = field_map[sh_name]
                replayed = extract(chains, c, lo, hi)
                if replayed != defects[sh_name]:
                    raise Refused("stock dump mismatch: %s replayed 0x%X != defects shadow 0x%X"
                                  % (sh_name, replayed, defects[sh_name]))

    fp = fingerprint(rows, last)
    baseline = {
        "last_row": last,
        "fingerprint": fp,
        "die_id_hash": dump["die_id_hash"],
    }
    if "die_id" in dump:
        baseline["die_id"] = dump["die_id"]
    print("%s: rows %d-%d used, fingerprint %s  die_id_hash %s" % (
        args.card, FF_START, last, fp, baseline["die_id_hash"],
    ))

    plans = {}
    if "noop" in args.plans:
        if 1 not in chains or 7 not in chains[1]:
            raise Refused("cannot build 0_noop: chain 1 block 7 not present in baseline dump")
        plans["0_noop"] = {"mode": "noop", "records": [
            record(1, 7, chains[1][7], chains[1][7], "mechanism test, value unchanged")]}
    if "sm_hbm" in args.plans:
        plans["sm_hbm"] = {"mode": "sm_hbm",
                           "records": [record(*r) for r in field_plan(chains, SM_HBM, defects)],
                           "expect_fields": {f[0]: "0x%X" % defects[f[4]] for f in SM_HBM}}
    if "pcie" in args.plans:
        wrong = ["block %d is 0x%04X, not 0x%04X" % (b, chains.get(c, {}).get(b, 0), old)
                 for c, b, old, _, _ in PCIE if chains.get(c, {}).get(b, 0) != old]
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

    # Assign rows in burn order, record prior_records for each plan, and replay in physical row order.
    row = last + 1 + args.skip_rows
    sim_rows = dict(rows)
    cumulative_prior = []
    plan_set_meta = []
    active_keys = []
    for key in PLAN_ORDER:
        plan = plans.get(key)
        if plan is None:
            continue
        if not plan["records"]:
            print("SKIP %s: already at target, nothing to burn" % key)
            del plans[key]
            continue
        first_row = row
        plan["prior_records"] = list(cumulative_prior)
        for r in plan["records"]:
            if row > FF_END:
                raise Refused("out of blank rows")
            r["row"] = row
            sim_rows[row] = int(r["encoded"], 16)
            cumulative_prior.append({"row": row, "encoded": r["encoded"]})
            row += 1
        fname = "%s_plan_%s.json" % (args.card, key)
        plan_set_meta.append({
            "file": fname,
            "key": key,
            "mode": plan["mode"],
            "first_row": first_row,
            "last_row": row - 1,
            "count": len(plan["records"]),
        })
        active_keys.append(key)

    merged = replay(sim_rows)
    for key in active_keys:
        plan = plans[key]
        plan.update(
            schema_version=2,
            card=args.card,
            order=PLAN_ORDER.index(key),
            skip_rows=args.skip_rows,
            source_dump=os.path.basename(args.dump),
            source_defects=defects_src,
            baseline=dict(baseline),
            plan_set=list(plan_set_meta),
            unchanged_fields={n: "0x%X" % extract(chains, c, lo, hi)
                              for n, c, lo, hi in UNCHANGED},
        )

    for name, c, lo, hi, dname in SM_HBM + NVLINK:
        sel = "sm_hbm" if (name, c, lo, hi, dname) in SM_HBM else "nvlink"
        if sel not in plans:
            continue
        got, want = extract(merged, c, lo, hi), defects[dname]
        print("  %-22s 0x%-8X -> 0x%-8X %s" % (name, extract(chains, c, lo, hi), got,
                                               "OK" if got == want else "FAIL want 0x%X" % want))
        if got != want:
            raise Refused("physical replay mismatch on %s: got 0x%X want 0x%X" % (name, got, want))
    for name, c, lo, hi in UNCHANGED:
        if extract(merged, c, lo, hi) != extract(chains, c, lo, hi):
            raise Refused("unchanged field %s altered by plan!" % name)
        print("  %-22s 0x%X unchanged" % (name, extract(chains, c, lo, hi)))

    # Verify every changed bit across the entire physical replay belongs to authorized fields.
    auth_masks = authorized_bit_masks_for_plans([(k, plans[k]) for k in active_keys])
    for c in set(chains) | set(merged):
        for b in set(chains.get(c, {})) | set(merged.get(c, {})):
            diff = chains.get(c, {}).get(b, 0) ^ merged.get(c, {}).get(b, 0)
            if diff & ~auth_masks.get((c, b), 0):
                raise Refused("unauthorized bit diff 0x%04X in block (%d, %d)" % (diff, c, b))

    os.makedirs(args.out_dir, exist_ok=True)
    # Prevent stale leftover plan files from earlier derive runs!
    existing = sorted(
        glob.glob(os.path.join(args.out_dir, "%s_plan_*.json" % args.card))
        + glob.glob(os.path.join(args.out_dir, "%s_manifest.json" % args.card))
    )
    if existing and not args.force:
        raise Refused("existing plan/manifest files in %s (use --force to cleanly replace): %s"
                      % (args.out_dir, ", ".join(os.path.basename(p) for p in existing)))
    for stale in existing:
        os.remove(stale)

    for key in active_keys:
        plan = plans[key]
        name = "%s_plan_%s.json" % (args.card, key)
        path = os.path.join(args.out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(plan, f, indent=2)
            f.write("\n")
        print("\n%s" % name)
        for i, r in enumerate(plan["records"]):
            print("  %-2d row %d = %s  chain %d block %-2d %s -> %s%s" % (
                i, r["row"], r["encoded"], r["chain"], r["block"], r["old_data"], r["new_data"],
                "  SETS %s" % r["sets_bits"] if "sets_bits" in r else ""))

    manifest = {
        "schema_version": 2,
        "card": args.card,
        "baseline": baseline,
        "skip_rows": args.skip_rows,
        "plans": plan_set_meta,
    }
    manifest_path = os.path.join(args.out_dir, "%s_manifest.json" % args.card)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return 0


def validate_plan_records(plans):
    seen_rows = set()
    unchanged_sets = set()
    plan_row_map = {}
    for path, plan in plans:
        mode = plan.get("mode")
        if mode not in KNOWN_MODES:
            raise Refused("plan %s has unknown mode %r" % (path, mode))
        recs = plan.get("records")
        if not isinstance(recs, list) or not recs:
            raise Refused("plan %s has no records" % path)
        unchanged = plan.get("unchanged_fields")
        if not isinstance(unchanged, dict):
            raise Refused("plan %s missing unchanged_fields" % path)
        for name, _, _, _ in UNCHANGED:
            if name not in unchanged:
                raise Refused("plan %s missing unchanged_fields.%s" % (path, name))
        unchanged_sets.add(json.dumps(unchanged, sort_keys=True))
        for i, r in enumerate(recs):
            row = r.get("row")
            c = r.get("chain")
            b = r.get("block")
            if not isinstance(row, int) or isinstance(row, bool) or not (FF_START <= row <= FF_END):
                raise Refused("plan %s record %d has invalid row %r" % (path, i, row))
            if row in seen_rows:
                raise Refused("duplicate target row %d across plans" % row)
            seen_rows.add(row)
            if (c, b) in FORBIDDEN:
                raise Refused("plan %s record %d targets forbidden device-ID block (%s, %s)"
                              % (path, i, c, b))
            try:
                enc = int(r["encoded"], 16)
                old_d = int(r["old_data"], 16)
                new_d = int(r["new_data"], 16)
            except (KeyError, TypeError, ValueError) as exc:
                raise Refused("plan %s record %d malformed: %s" % (path, i, exc)) from exc
            if enc & 0x20:
                raise Refused("plan %s record %d sets IFF bit (bit 5)" % (path, i))
            if (old_d ^ new_d) & FORBIDDEN_BITS.get((c, b), 0):
                raise Refused("plan %s record %d modifies forbidden device-ID bit in (%s, %s)"
                              % (path, i, c, b))
            want_enc = (new_d << 16) | (b << 6) | c
            if enc != want_enc:
                raise Refused("plan %s record %d encoded 0x%08X != expected 0x%08X"
                              % (path, i, enc, want_enc))
            plan_row_map[row] = enc
    if len(unchanged_sets) != 1:
        raise Refused("plans disagree on unchanged_fields")

    # Enforce complete prefix: if any passed plan lists prior_records (from an earlier
    # plan derived in the same run, e.g. 0_noop before sm_hbm), those earlier plans MUST
    # also be included so check/verify cannot silently omit preceding rows.
    for path, plan in plans:
        for pr in plan.get("prior_records", []):
            pr_row = pr.get("row")
            pr_enc = _parse_u32(pr.get("encoded"), "prior_records.encoded")
            if pr_row not in plan_row_map:
                raise Refused(
                    "plan %s depends on missing preceding plan record at row %d (%s) — "
                    "pass all preceding plans from the same derive run"
                    % (os.path.basename(path), pr_row, pr.get("encoded"))
                )
            if plan_row_map[pr_row] != pr_enc:
                raise Refused(
                    "plan %s expects preceding row %d = %s, but passed plan has 0x%08X"
                    % (os.path.basename(path), pr_row, pr.get("encoded"), plan_row_map[pr_row])
                )


def load_plans(paths):
    plans = [(p, load_json(p)) for p in paths]
    bases = {json.dumps(pl.get("baseline"), sort_keys=True) for _, pl in plans}
    if len(bases) != 1 or not plans[0][1].get("baseline"):
        raise Refused("plans must come from one ffcard.py derive run (baseline differs or missing)")
    base = plans[0][1]["baseline"]
    if not isinstance(base.get("die_id_hash"), str) or len(base["die_id_hash"]) != 16:
        raise Refused("plan baseline is missing required die_id_hash (re-derive with current ffcard.py)")
    validate_plan_records(plans)
    plans.sort(key=lambda x: x[1]["records"][0]["row"])
    return plans, base


def compare(dump, plans, base, stage):
    """Per-record state against the plans. Returns (rows, burned, pending, problems)."""
    problems = check_dump_health(dump, stage=stage)
    if dump.get("die_id_hash") != base["die_id_hash"]:
        problems.append("die_id_hash %r != plan baseline %r: NOT the planned card"
                        % (dump.get("die_id_hash"), base["die_id_hash"]))
    if "die_id" in base and dump.get("die_id") != base["die_id"]:
        problems.append("die_id rows 8-15 differ from plan baseline: NOT the planned card")
    rows = load_rows(dump)
    fp = fingerprint(rows, base["last_row"])
    if fp != base["fingerprint"]:
        problems.append("rows %d-%d fingerprint %s, plan baseline %s: NOT the planned card/state"
                        % (FF_START, base["last_row"], fp, base["fingerprint"]))
        return rows, [], [], problems

    # Check every planned record in physical row order.
    burned, pending, plan_rows = [], [], set()
    baseline_chains = replay(rows, upto=base["last_row"])
    running_chains = {c: dict(bm) for c, bm in baseline_chains.items()}
    for path, plan in plans:
        for i, r in enumerate(plan["records"]):
            rnum = r["row"]
            c, b = r["chain"], r["block"]
            want_old = int(r["old_data"], 16)
            cur_old = running_chains.get(c, {}).get(b, 0)
            if cur_old != want_old:
                problems.append(
                    "plan %s record %d expects block (%d,%d) old_data 0x%04X, but replayed state is 0x%04X"
                    % (os.path.basename(path), i, c, b, want_old, cur_old)
                )
            running_chains.setdefault(c, {})[b] = int(r["new_data"], 16)

            got, want = rows[rnum], int(r["encoded"], 16)
            plan_rows.add(rnum)
            item = (os.path.basename(path), i, rnum, r["encoded"])
            if got == want:
                if pending:
                    problems.append("row %d burned after an unburned row %d" % (rnum, pending[0][2]))
                burned.append(item)
            elif got == 0:
                pending.append(item)
            else:
                problems.append("row %d = 0x%08X, plan %s" % (rnum, got, r["encoded"]))

    stray = [i for i in range(base["last_row"] + 1, FF_END + 1) if rows[i] and i not in plan_rows]
    if stray:
        problems.append("rows outside the plans are written: %s" % stray)
    return rows, burned, pending, problems


def check(args):
    plans, base = load_plans(args.plans)
    rows, burned, pending, problems = compare(load_json(args.dump), plans, base, stage="check")
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
    rows, burned, pending, problems = compare(dump, plans, base, stage="verify")
    for name, i, row, enc in pending:
        problems.append("not burned: %s index %d (row %d = %s)" % (name, i, row, enc))

    baseline_chains = replay(rows, upto=base["last_row"])
    chains = replay(rows)
    fields = {f[0]: f for f in SM_HBM + NVLINK}
    shadow_dict = dump.get("shadow")
    if not isinstance(shadow_dict, dict):
        problems.append("dump is missing required 'shadow' register dict")
        shadow_dict = {}

    # Enforce canonical expected fields per plan mode (never trust truncated expect_fields).
    need_final_defects = []
    expected_targets = {}
    for path, plan in plans:
        mode = plan["mode"]
        canon = canonical_fields_for_mode(mode)
        plan_expect = plan.get("expect_fields") or {}
        if set(plan_expect.keys()) != set(canon):
            problems.append("plan %s expect_fields keys %s != canonical %s for mode %s"
                            % (os.path.basename(path), sorted(plan_expect.keys()), sorted(canon), mode))
            continue
        for name in canon:
            want_val = _parse_u32(plan_expect[name], "expect_fields.%s" % name)
            expected_targets[name] = want_val
            need_final_defects.append(fields[name][4])
            if name in DEFECT_FILE_SHADOWS:
                need_final_defects.append(name)

    # Verify every changed bit between baseline and final physical replay is authorized!
    auth_masks = authorized_bit_masks_for_plans(plans)
    for c in set(baseline_chains) | set(chains):
        for b in set(baseline_chains.get(c, {})) | set(chains.get(c, {})):
            diff = baseline_chains.get(c, {}).get(b, 0) ^ chains.get(c, {}).get(b, 0)
            if diff & ~auth_masks.get((c, b), 0):
                problems.append("unauthorized bit change 0x%04X in block (%d, %d)" % (diff, c, b))

    for name, want_val in expected_targets.items():
        _, c, lo, hi, _ = fields[name]
        got = extract(chains, c, lo, hi)
        print("  %-22s 0x%-8X %s" % (name, got, "OK" if got == want_val else "FAIL want 0x%X" % want_val))
        if got != want_val:
            problems.append("%s = 0x%X, want 0x%X" % (name, got, want_val))
        if name in SHADOWED:
            shadow = shadow_dict.get(name)
            if shadow is None:
                problems.append("missing required shadow register %s" % name)
            elif _parse_u32(shadow, "shadow.%s" % name) != want_val:
                problems.append("shadow %s = %s, want 0x%X" % (name, shadow, want_val))

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
            elif _parse_u32(sh, "shadow.%s" % name) != want:
                problems.append("shadow %s = %s, want unchanged 0x%X" % (name, sh, want))

    # Final same-card defects + OPT_PES_DISABLE / OPT_ROP_L2_DISABLE shadows are MANDATORY
    # whenever any defect-targeted plan (sm_hbm / nvlink) is verified!
    if need_final_defects:
        try:
            regs, _ = resolve_defects(dump, args.defects, need_final_defects)
        except Refused as exc:
            problems.append("final defects check failed: %s" % exc)
        else:
            for name, want_val in expected_targets.items():
                dname = fields[name][4]
                if regs[dname] != want_val:
                    problems.append("final defect mask %s = 0x%X, planned for 0x%X"
                                    % (dname, regs[dname], want_val))
                if name in DEFECT_FILE_SHADOWS:
                    if regs[name] != want_val:
                        problems.append("final shadow %s = 0x%X, want 0x%X"
                                        % (name, regs[name], want_val))

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
    p = sub.add_parser("derive", help="write per-card burn plans from cold stock dump")
    p.add_argument("--card", required=True, help="name used in the plan file names")
    p.add_argument("--dump", required=True, help="cold stock ff_dump.py JSON (includes defects + die_id)")
    p.add_argument("--defects", default=None,
                   help="optional separate defects JSON (MUST carry matching die_id_hash)")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--plans", nargs="+", default=["noop", "sm_hbm", "pcie", "nvlink"],
                   choices=["noop", "sm_hbm", "pcie", "nvlink"])
    p.add_argument("--skip-rows", type=int, default=0,
                   help="blank rows to leave before the first record (default 0, must be >= 0)")
    p.add_argument("--force", action="store_true", help="cleanly replace existing plan files")
    p.set_defaults(fn=derive)
    p = sub.add_parser("check", help="in-window check (DSOV=0) before burning")
    p.add_argument("--dump", required=True, help="fresh in-window ff_dump.py JSON (DSOV=0)")
    p.add_argument("plans", nargs="+")
    p.set_defaults(fn=check)
    p = sub.add_parser("verify", help="post-burn verification after a cold boot (DSOV=1)")
    p.add_argument("--dump", required=True, help="cold-boot ff_dump.py JSON (DSOV=1, includes defects)")
    p.add_argument("--defects", default=None,
                   help="optional separate cold-boot defects JSON (MUST carry matching die_id_hash)")
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
