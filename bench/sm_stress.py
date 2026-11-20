#!/usr/bin/env python3
"""SM-targeted FP32 FMA stress through libcuda + hand-written PTX (no compiler needed).

Each block reads %smid. Blocks on SMs in the selected set run a dense FFMA loop for
a fixed number of SM clock cycles; blocks on other SMs exit at once. Every launch
records which SM ids received a block, so coverage is checked, not assumed.

usage:
  sm_stress.py probe                      list the SM ids that exist
  sm_stress.py run SET SECONDS            SET = all | lo | hi | q0..q3 | ids:3,7,9
     lo/hi = first/second half of the sorted SM id list; q0..q3 = quarters.
Exit 0 = ran to the end. A lost GPU shows as a CUDA error (exit 2).
"""
import ctypes, sys, time

cuda = ctypes.CDLL("libcuda.so.1")


def ck(code, what):
    if code != 0:
        p = ctypes.c_char_p()
        cuda.cuGetErrorString(code, ctypes.byref(p))
        print(time.strftime("%H:%M:%S"), f"CUDA-ERROR {what}: {code} {p.value.decode() if p.value else ''}", flush=True)
        sys.exit(2)


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


T0 = time.time()
def log(*a):
    print(time.strftime("%H:%M:%S"), f"t={time.time()-T0:7.1f}", *a, flush=True)


ck(cuda.cuInit(0), "cuInit")
dev = ctypes.c_int(); ck(cuda.cuDeviceGet(ctypes.byref(dev), 0), "cuDeviceGet")
nsm = ctypes.c_int(); ck(cuda.cuDeviceGetAttribute(ctypes.byref(nsm), 16, dev), "attr SM count")
tmo = ctypes.c_int(); ck(cuda.cuDeviceGetAttribute(ctypes.byref(tmo), 17, dev), "attr exec timeout")
clk = ctypes.c_int(); ck(cuda.cuDeviceGetAttribute(ctypes.byref(clk), 13, dev), "attr clock kHz")
ctx = ctypes.c_void_p(); ck(cuda.cuCtxCreate_v2(ctypes.byref(ctx), 0, dev), "cuCtxCreate")
mod = ctypes.c_void_p(); ck(cuda.cuModuleLoadData(ctypes.byref(mod), build_ptx().encode() + b"\0"), "cuModuleLoadData")
fn = ctypes.c_void_p(); ck(cuda.cuModuleGetFunction(ctypes.byref(fn), mod, b"burn"), "cuModuleGetFunction")

BLOCKS, THREADS = nsm.value * 2, 512
d_mask, d_hits, d_out = ctypes.c_uint64(), ctypes.c_uint64(), ctypes.c_uint64()
ck(cuda.cuMemAlloc_v2(ctypes.byref(d_mask), 32), "alloc mask")
ck(cuda.cuMemAlloc_v2(ctypes.byref(d_hits), 1024), "alloc hits")
ck(cuda.cuMemAlloc_v2(ctypes.byref(d_out), BLOCKS * THREADS * 4), "alloc out")
log(f"SMs={nsm.value} clock={clk.value/1000:.0f}MHz exec_timeout={tmo.value} blocks={BLOCKS}x{THREADS}")


def launch(ids, cycles):
    mask = (ctypes.c_uint32 * 8)()
    for i in ids:
        mask[i >> 5] |= 1 << (i & 31)
    ck(cuda.cuMemcpyHtoD_v2(d_mask, mask, 32), "copy mask")
    ck(cuda.cuMemsetD8_v2(d_hits, 0, 1024), "clear hits")
    cyc = ctypes.c_uint64(cycles)
    args = (ctypes.c_void_p * 4)(*[ctypes.cast(ctypes.byref(v), ctypes.c_void_p) for v in (d_mask, d_hits, d_out, cyc)])
    ck(cuda.cuLaunchKernel(fn, BLOCKS, 1, 1, THREADS, 1, 1, 0, None, args, None), "launch")
    ck(cuda.cuCtxSynchronize(), "sync")
    hits = (ctypes.c_uint32 * 256)()
    ck(cuda.cuMemcpyDtoH_v2(hits, d_hits, 1024), "copy hits")
    return [i for i in range(256) if hits[i]]


present = sorted(launch(range(256), 1000))
log(f"present SM ids ({len(present)}): {present}")
if sys.argv[1] == "probe":
    sys.exit(0)

sel, dur = sys.argv[2], float(sys.argv[3])
n = len(present)
if sel == "all": ids = present
elif sel == "lo": ids = present[: n // 2]
elif sel == "hi": ids = present[n // 2:]
elif sel[0] == "q": q = int(sel[1]); ids = present[q * n // 4:(q + 1) * n // 4]
elif sel.startswith("ids:"): ids = [int(x) for x in sel[4:].split(",")]
else: raise SystemExit("bad SET")
log(f"STRESS set={sel} n={len(ids)} ids={ids} for {dur:.0f}s")
cycles = int(clk.value * 1000 * 0.25)  # about 0.25 s per launch at the max clock (exec timeout is on)
k = 0; last = 0
while time.time() - T0 < dur:
    got = launch(ids, cycles); k += 1
    miss = [i for i in ids if i not in got]
    if miss:
        log(f"WARNING launch {k}: no block reached SM ids {miss}")
    if time.time() - last > 10:
        log(f"launch {k} ok, covered {len([i for i in ids if i in got])}/{len(ids)} target SMs")
        last = time.time()
log(f"END set={sel} launches={k}")
