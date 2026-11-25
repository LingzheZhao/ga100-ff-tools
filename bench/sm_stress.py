#!/usr/bin/env python3
"""SM-targeted FP32 FMA stress through libcuda + hand-written PTX (no compiler needed).

Hardened GPU targeting & SM coverage guarantees:
  - Supports explicit --bdf (via cuDeviceGetByPCIBusId) or --device ordinal;
    refuses ambiguous default when >1 CUDA device is present.
  - Prints resolved PCI bus ID and GPU UUID before stressing so logs bind to
    the exact physical card.
  - Probes up to 10 launches to discover all reported SMs (fails non-zero if
    discovered SM count != driver SM count or != --expected-sms).
  - Tracks cumulative SM coverage across all launches and EXITS NON-ZERO (1)
    if any target SM was missed (or on CUDA error, exit 2).

usage:
  sm_stress.py --bdf 0000:01:00.0 probe [--expected-sms 108]
  sm_stress.py --bdf 0000:01:00.0 run SET SECONDS [--expected-sms 108]
     SET = all | lo | hi | q0..q3 | ids:3,7,9
"""
import argparse
import ctypes
import sys
import time


def build_ptx():
    fma = []
    for _ in range(16):
        for k in range(1, 9):
            fma.append(f"  fma.rn.f32 %f{k}, %f{k}, %f9, %f10;")
    init = "\n".join(f"  add.f32 %f{k}, %f1, 0f3F{k:01X}00000;" for k in range(2, 9))
    sumc = "\n".join(f"  add.f32 %f11, %f11, %f{k};" for k in range(2, 9))
    return f"""
.version 7.0
.target sm_80
.address_size 64

.visible .entry burn(.param .u64 p_mask, .param .u64 p_hits, .param .u64 p_out, .param .u64 p_cycles)
{{
  .reg .pred %p<4>;
  .reg .b32 %r<16>;
  .reg .b64 %rd<16>;
  .reg .f32 %f<16>;
  ld.param.u64 %rd1, [p_mask];
  ld.param.u64 %rd2, [p_hits];
  ld.param.u64 %rd3, [p_out];
  ld.param.u64 %rd4, [p_cycles];
  mov.u32 %r1, %smid;
  mov.u32 %r2, %tid.x;
  setp.ne.u32 %p1, %r2, 0;
  mul.wide.u32 %rd5, %r1, 4;
  add.u64 %rd6, %rd2, %rd5;
  @!%p1 atom.global.add.u32 %r3, [%rd6], 1;
  shr.u32 %r4, %r1, 5;
  and.b32 %r5, %r1, 31;
  mul.wide.u32 %rd7, %r4, 4;
  add.u64 %rd8, %rd1, %rd7;
  ld.global.u32 %r6, [%rd8];
  shr.u32 %r7, %r6, %r5;
  and.b32 %r7, %r7, 1;
  setp.eq.u32 %p2, %r7, 0;
  @%p2 bra DONE;
  cvt.rn.f32.u32 %f1, %r2;
  mul.f32 %f1, %f1, 0f3A800000;
{init}
  mov.f32 %f9, 0f3F7FFFFE;
  mov.f32 %f10, 0f3A000000;
  mov.u64 %rd9, %clock64;
LOOP:
{chr(10).join(fma)}
  mov.u64 %rd10, %clock64;
  sub.u64 %rd11, %rd10, %rd9;
  setp.lt.u64 %p3, %rd11, %rd4;
  @%p3 bra LOOP;
  mov.f32 %f11, %f1;
{sumc}
  mov.u32 %r8, %ctaid.x;
  mov.u32 %r9, %ntid.x;
  mad.lo.u32 %r10, %r8, %r9, %r2;
  mul.wide.u32 %rd12, %r10, 4;
  add.u64 %rd13, %rd3, %rd12;
  st.global.f32 [%rd13], %f11;
DONE:
  ret;
}}
"""


def select_ids(present, sel):
    n = len(present)
    if sel == "all":
        return list(present)
    if sel == "lo":
        return list(present[: n // 2])
    if sel == "hi":
        return list(present[n // 2:])
    if len(sel) == 2 and sel[0] == "q" and sel[1] in "0123":
        q = int(sel[1])
        return list(present[q * n // 4:(q + 1) * n // 4])
    if sel.startswith("ids:"):
        ids = [int(x) for x in sel[4:].split(",") if x.strip()]
        if not ids:
            raise ValueError("empty ids list")
        missing = [i for i in ids if i not in present]
        if missing:
            raise ValueError("requested SM ids not present on GPU: %s" % missing)
        return ids
    raise ValueError("bad SET %r (expected all|lo|hi|q0..q3|ids:...)" % (sel,))


def evaluate_coverage(target_ids, cumulative_hits, expected_sms=None, reported_nsm=None, sel="all"):
    """Return list of failure reasons (empty list = PASS)."""
    problems = []
    if expected_sms is not None and reported_nsm is not None and reported_nsm != expected_sms:
        problems.append("driver reported %d SMs, expected %d" % (reported_nsm, expected_sms))
    missed = sorted(set(target_ids) - set(cumulative_hits))
    if missed:
        problems.append("SMs never hit during run (%d/%d missed): %s"
                        % (len(missed), len(target_ids), missed))
    if expected_sms is not None and sel == "all" and len(set(cumulative_hits) & set(target_ids)) < expected_sms:
        problems.append("covered only %d SMs, expected %d"
                        % (len(set(cumulative_hits) & set(target_ids)), expected_sms))
    return problems


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="SM-targeted FP32 FMA stress with BDF binding & coverage gate")
    ap.add_argument("--bdf", default=None, help="PCI bus ID (e.g. 0000:01:00.0); recommended on multi-GPU hosts")
    ap.add_argument("--device", type=int, default=None, help="explicit CUDA ordinal (alternative to --bdf)")
    ap.add_argument("--expected-sms", type=int, default=None,
                    help="fail non-zero if driver SM count or covered SM count != expected")
    ap.add_argument("--strict-per-launch", action="store_true",
                    help="fail non-zero if ANY single launch misses a target SM")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("probe", help="discover and verify all present SM ids")
    p_run = sub.add_parser("run", help="run FP32 FMA stress on target SM set")
    p_run.add_argument("set_spec", help="all | lo | hi | q0..q3 | ids:3,7,9")
    p_run.add_argument("seconds", type=float, help="stress duration in seconds")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.bdf and args.device is not None:
        print("ERROR: pass either --bdf or --device, not both", file=sys.stderr)
        return 2

    cuda = ctypes.CDLL("libcuda.so.1")
    t0 = time.time()

    def log(*a):
        print(time.strftime("%H:%M:%S"), f"t={time.time() - t0:7.1f}", *a, flush=True)

    def ck(code, what):
        if code != 0:
            p = ctypes.c_char_p()
            cuda.cuGetErrorString(code, ctypes.byref(p))
            log(f"CUDA-ERROR {what}: {code} {p.value.decode() if p.value else ''}")
            sys.exit(2)

    ck(cuda.cuInit(0), "cuInit")
    count = ctypes.c_int()
    ck(cuda.cuDeviceGetCount(ctypes.byref(count)), "cuDeviceGetCount")
    if count.value <= 0:
        log("ERROR: no CUDA devices found")
        return 2

    dev = ctypes.c_int()
    if args.bdf:
        ck(cuda.cuDeviceGetByPCIBusId(ctypes.byref(dev), args.bdf.encode("ascii")), "cuDeviceGetByPCIBusId")
    elif args.device is not None:
        ck(cuda.cuDeviceGet(ctypes.byref(dev), args.device), "cuDeviceGet")
    else:
        if count.value > 1:
            log(f"ERROR: {count.value} CUDA devices present; pass --bdf or --device explicitly")
            return 2
        ck(cuda.cuDeviceGet(ctypes.byref(dev), 0), "cuDeviceGet")

    pcibus = ctypes.create_string_buffer(32)
    ck(cuda.cuDeviceGetPCIBusId(pcibus, 32, dev), "cuDeviceGetPCIBusId")
    uuid_buf = (ctypes.c_ubyte * 16)()
    uuid_str = "unknown"
    if hasattr(cuda, "cuDeviceGetUuid") and cuda.cuDeviceGetUuid(uuid_buf, dev) == 0:
        hx = "".join(f"{b:02x}" for b in uuid_buf)
        uuid_str = f"GPU-{hx[0:8]}-{hx[8:12]}-{hx[12:16]}-{hx[16:20]}-{hx[20:32]}"

    nsm = ctypes.c_int()
    ck(cuda.cuDeviceGetAttribute(ctypes.byref(nsm), 16, dev), "attr SM count")
    tmo = ctypes.c_int()
    ck(cuda.cuDeviceGetAttribute(ctypes.byref(tmo), 17, dev), "attr exec timeout")
    clk = ctypes.c_int()
    ck(cuda.cuDeviceGetAttribute(ctypes.byref(clk), 13, dev), "attr clock kHz")
    ctx = ctypes.c_void_p()
    ck(cuda.cuCtxCreate_v2(ctypes.byref(ctx), 0, dev), "cuCtxCreate")
    mod = ctypes.c_void_p()
    ck(cuda.cuModuleLoadData(ctypes.byref(mod), build_ptx().encode() + b"\0"), "cuModuleLoadData")
    fn = ctypes.c_void_p()
    ck(cuda.cuModuleGetFunction(ctypes.byref(fn), mod, b"burn"), "cuModuleGetFunction")

    blocks, threads = nsm.value * 4, 512
    d_mask, d_hits, d_out = ctypes.c_uint64(), ctypes.c_uint64(), ctypes.c_uint64()
    ck(cuda.cuMemAlloc_v2(ctypes.byref(d_mask), 32), "alloc mask")
    ck(cuda.cuMemAlloc_v2(ctypes.byref(d_hits), 1024), "alloc hits")
    ck(cuda.cuMemAlloc_v2(ctypes.byref(d_out), blocks * threads * 4), "alloc out")
    log(f"target bdf={pcibus.value.decode()} uuid={uuid_str} SMs={nsm.value} "
        f"clock={clk.value / 1000:.0f}MHz exec_timeout={tmo.value} blocks={blocks}x{threads}")

    def launch(ids, cycles):
        mask = (ctypes.c_uint32 * 8)()
        for i in ids:
            mask[i >> 5] |= 1 << (i & 31)
        ck(cuda.cuMemcpyHtoD_v2(d_mask, mask, 32), "copy mask")
        ck(cuda.cuMemsetD8_v2(d_hits, 0, 1024), "clear hits")
        cyc = ctypes.c_uint64(cycles)
        kargs = (ctypes.c_void_p * 4)(*[
            ctypes.cast(ctypes.byref(v), ctypes.c_void_p)
            for v in (d_mask, d_hits, d_out, cyc)
        ])
        ck(cuda.cuLaunchKernel(fn, blocks, 1, 1, threads, 1, 1, 0, None, kargs, None), "launch")
        ck(cuda.cuCtxSynchronize(), "sync")
        hits = (ctypes.c_uint32 * 256)()
        ck(cuda.cuMemcpyDtoH_v2(hits, d_hits, 1024), "copy hits")
        return [i for i in range(256) if hits[i]]

    # Probe multiple times so scheduling jitter cannot under-count present SMs.
    present_set = set()
    for _ in range(10):
        present_set.update(launch(range(256), 50000))
        if len(present_set) >= nsm.value:
            break
    present = sorted(present_set)
    log(f"present SM ids ({len(present)}/{nsm.value}): {present}")
    if len(present) != nsm.value:
        log(f"FAIL: probe observed {len(present)} SMs != driver SM count {nsm.value}")
        return 1
    if args.expected_sms is not None and nsm.value != args.expected_sms:
        log(f"FAIL: driver reported {nsm.value} SMs != --expected-sms {args.expected_sms}")
        return 1
    if args.cmd == "probe":
        return 0

    try:
        ids = select_ids(present, args.set_spec)
    except ValueError as exc:
        log(f"ERROR: {exc}")
        return 2
    dur = args.seconds
    log(f"STRESS set={args.set_spec} n={len(ids)} ids={ids} for {dur:.0f}s")
    cycles = int(clk.value * 1000 * 0.25)
    k = 0
    last = 0.0
    cumulative_hits = set()
    missed_launches = 0
    t_start = time.time()
    while time.time() - t_start < dur or k == 0:
        got = launch(ids, cycles)
        k += 1
        cumulative_hits.update(i for i in got if i in ids)
        miss = [i for i in ids if i not in got]
        if miss:
            missed_launches += 1
            log(f"WARNING launch {k}: no block reached SM ids {miss}")
        if time.time() - last > 10:
            log(f"launch {k} ok, this={len(ids) - len(miss)}/{len(ids)} "
                f"cumulative={len(cumulative_hits)}/{len(ids)}")
            last = time.time()

    problems = evaluate_coverage(
        ids, cumulative_hits, expected_sms=args.expected_sms,
        reported_nsm=nsm.value, sel=args.set_spec,
    )
    if args.strict_per_launch and missed_launches > 0:
        problems.append(f"{missed_launches}/{k} launches missed one or more target SMs")
    if problems:
        for p in problems:
            log(f"FAIL: {p}")
        return 1
    log(f"PASS set={args.set_spec} launches={k} cumulative_covered={len(cumulative_hits)}/{len(ids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
