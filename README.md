# ga100-ff-tools

> **USE AT YOUR OWN RISK.** These experimental tools are provided **AS IS**, without
> warranty. Fuse programming is physically irreversible and can permanently damage
> your GPU, VRM, board, or other hardware, or cause data loss. To the extent
> permitted by applicable law, the authors and contributors accept no liability
> for damage or loss arising from use of these tools.
>
> **Check every burn plan by hand, twice, before running it**: the intended card
> and its baseline rows, the defect masks, each chain/block edit and each encoded
> 32-bit word. The tools' own checks do not replace that review.
> **Agents must never run the arm or burn scripts** (see [AGENTS.md](AGENTS.md)).

Per-card fuseless-fuse (FF) tools for the NVIDIA CMP 170HX (GA100). After a
voltage glitch opens the fuse-programming window, they append FF records that
re-enable what the mining SKU disabled: GPCs/TPCs, the fifth HBM stack (80 GB),
PCIe Gen3/Gen4 and NVLink. They took three 8 GB cards to their full fuse-level
configuration.

Python 3.8+, standard library only, no third-party packages. The directory
layout matches the host layout the scripts run from (`/root/cmp170`). Glitching
itself is outside this repository (see [Glitching](#glitching)).

| Path | Writes to the GPU? | Purpose |
|---|---|---|
| `planner/ff_dump.py` | CMD_READ only | Read FF rows 222-487, decode records, rebuild chains, read option shadows. `--shadow-only` issues no fuse command. |
| `planner/read_defects.py` | No (read-only map) | Defect masks, PES/ROP_L2 disables, software-override state, as JSON. |
| `planner/ffcard.py` | No (offline) | Derive per-card plans; check a window dump before burning; verify after the cold boot. |
| `planner/pcie_state.py` | No (read-only map) | PCIe Gen3/Gen4 and NVLink shadows, LnkCap/LnkSta, against their targets. |
| `arm/sw_override.py` | Volatile register | `EN_SW_OVERRIDE` (0x820040). Sticks only when DSOV=0 (glitched). |
| `arm/open_wdata_plm.py` | Volatile register | Clears `WDATA_WR_SECURE` so `FUSEWDATA_PLM` opens. |
| `arm/arm_sense_ctrl.py` | Volatile register | One SENSE_CTRL (FUSECTRL=3): EFP 0->1 with DSOV kept 0; `--clear-sbfe`. |
| `burn/ff_burn.py` | **Burns one fuse row** | One record per call, dry-run by default, `--confirm` plus typing BURN. |
| `host/gpu-stack.sh` | No | Turn the NVIDIA driver and gpu-unlock off/on for the next boot. |
| `bench/bench.cu` | No (CUDA) | Benchmark: memory latency/bandwidth, tensor-core TF32/BF16/INT8, boost clock, PCIe, BAR1/feature report. GPL-2.0-only. |
| `bench/sm_stress.py` | No (CUDA) | FP32 FMA stress on chosen SM ids, with per-launch SM coverage check. |

Live scripts need Linux, root and the card's PCI memory decode enabled.

## Install on the GPU host

```sh
sudo mkdir -p /root/cmp170
sudo cp -r arm burn planner /root/cmp170/
sudo install -m 0755 host/gpu-stack.sh /usr/local/sbin/gpu-stack
```

`ffcard.py derive` runs anywhere. Plans can be made on a workstation and copied
to `/root/cmp170/burn/`.

## Workflow

Each card needs its own dump and its own plans, even at the same BDF. A plan
made for one die writes that die's TPC masks and row numbers onto another.

### 1. Quiet the card

The NVIDIA driver, gpu-unlock and anything else that touches the card must stay
off it for the whole session:

```sh
sudo gpu-stack disable     # kernel module_blacklist via a GRUB drop-in + masked units
# power off at the wall ~30 s, cold boot
BDF=0000:01:00.0 gpu-stack status    # next/this boot DISABLED, nothing loaded
```

A `modprobe.d` blacklist is not enough: `nvidia-modprobe` and udev still load
the module. `module_blacklist=` on the kernel command line stops every loader.

### 2. Stock dump

```sh
BDF=0000:01:00.0; C=/root/cmp170
sudo setpci -s $BDF COMMAND=0x0002:0x0002          # only if BAR0 reads 0xFFFFFFFF
sudo python3 $C/planner/ff_dump.py --bdf $BDF --out $C/planner/card-dump.json
sudo python3 $C/planner/read_defects.py $BDF > $C/planner/card-defects.json
```

Expect CRC 0x55, controller idle, no read errors, DSOV=1 and `PCIE_DEVIDA`
0x20C2. Keep both files with the card; every later check refers to them.

### 3. Derive the plans (offline)

```sh
python3 planner/ffcard.py derive --card mycard \
    --dump card-dump.json --defects card-defects.json --out-dir plans/
```

It refuses a dump with read errors, holes in the used rows, IFF-marked rows, rows
that do not replay to the dump's chains, or a defects file missing a mask (an
unknown mask is never taken as zero). Then it writes up to four plans, with rows
assigned in burn order from the first blank row:

| Plan | Records | Change |
|---|---|---|
| `mycard_plan_0_noop.json` | 1 | Re-writes chain 1 block 7 with its current value: tests the mechanism, changes nothing. |
| `mycard_plan_sm_hbm.json` | ~11-12 | GPC, TPC (per GPC), PES, FBP, FBPA, FBIO and ROP_L2 disables down to their defect masks. **All in one window.** |
| `mycard_plan_pcie.json` | 4 | Clears `DISABLE_GEN3_SPEED` and the boot Gen2/3 gates; `PCIE_MAGIC_BITS_D` 0x16680000 -> 0x00200000 (Gen4). |
| `mycard_plan_nvlink.json` | 1 | `NVLINK_DISABLE` down to `NVLINK_DEFECTIVE`, keeping SYS_PIPE. |

Every record may only clear or set bits inside its target fields (it asserts
this); a record that would set a bit is marked `sets_bits`. Chain 2 blocks 37/38
(the PCIe device ID) are never emitted. `SYS_PIPE_DISABLE` and the device ID are
checked unchanged. The PCIe plan uses values proven on four dies and is skipped
when any of the four blocks differs from the expected stock value. A plan that
would change nothing is not written.

Options: `--plans noop sm_hbm pcie nvlink` to pick a subset, `--skip-rows N` to
leave N blank rows before the first record,
`--force` to overwrite existing plan files.

Each plan carries `baseline` (last used row and a fingerprint of rows 222..last)
plus its targets (`expect_fields`, `expect_registers`, `unchanged_fields`), so
the plans alone are enough for the checks below.

Read every record before going on. The sm_hbm output prints each field
before -> after against its defect mask.

Copy the plans to the host:

```sh
scp plans/mycard_plan_*.json gpuhost:/tmp/
sudo install -m 0644 /tmp/mycard_plan_*.json /root/cmp170/burn/   # on the host
```

### 4. Glitch, then arm (human only)

Glitching is outside this repository (see [Glitching](#glitching)).
After a Goldilocks glitch, CRC=0x55 and DSOV=0 but EFP=0, so the card cannot burn
yet. In the window, as root:

```sh
BDF=0000:01:00.0; C=/root/cmp170
python3 $C/planner/ff_dump.py --bdf $BDF --shadow-only | head -3   # CRC=0x55, idle=True
python3 $C/arm/sw_override.py    --bdf $BDF
python3 $C/arm/open_wdata_plm.py --bdf $BDF
python3 $C/arm/arm_sense_ctrl.py --bdf $BDF               # dry-run
python3 $C/arm/arm_sense_ctrl.py --bdf $BDF --confirm     # type SENSE; must end ARMED
python3 $C/arm/arm_sense_ctrl.py --bdf $BDF --clear-sbfe  # readback 0x0 OK
python3 $C/arm/sw_override.py    --bdf $BDF --read-only
python3 $C/arm/open_wdata_plm.py --bdf $BDF --read-only
```

Only one SENSE_CTRL per window: `RESENSE_DISABLE` reads 1 afterwards.

### 5. Window check

```sh
python3 $C/planner/ff_dump.py --bdf $BDF --out $C/planner/card-dump-window.json
python3 $C/planner/ffcard.py check --dump $C/planner/card-dump-window.json $C/burn/mycard_plan_*.json
```

It requires CRC 0x55 and idle, the baseline rows to hash to the plans'
fingerprint (same card, nothing new written), every plan row blank or already
holding its own record, burned records forming a prefix, and nothing written
outside the plans. On success it prints the next record:

```
baseline rows 222-291: match
burned 0, pending 17
OK to burn. Next: --plan mycard_plan_0_noop.json --index 0  (row 292 = 0x019801C1)
```

After a lost window it shows where to resume. `ffcard.py fingerprint --dump D`
prints the hash, for checking a card without the plans.

### 6. Burn (human only)

```sh
cd $C/burn
python3 ff_burn.py --bdf $BDF --plan mycard_plan_0_noop.json --index 0             # dry-run
python3 ff_burn.py --bdf $BDF --plan mycard_plan_0_noop.json --index 0 --confirm   # type BURN
for plan in sm_hbm pcie nvlink; do
  n=$(python3 -c "import json;print(len(json.load(open('mycard_plan_$plan.json'))['records']))")
  for i in $(seq 0 $((n - 1))); do
    python3 ff_burn.py --bdf $BDF --plan mycard_plan_$plan.json --index $i || break 2
    python3 ff_burn.py --bdf $BDF --plan mycard_plan_$plan.json --index $i --confirm || break 2
  done
done
```

Before typing BURN, compare the printed `target:` line with the plan. Anything
other than BURN aborts without writing. `ff_burn.py` checks IDLE, CRC 0x55,
DSOV=0, SBFE=0, EFP=1, both PLMs open, DEBUGCTRL.RWL=0 and a blank target row,
then writes, reads back and verifies.

Stop rules:

- `arm_sense_ctrl.py` reports WINDOW LOST: power off and glitch again. Nothing was burned.
- `STOP: EFP still 0`, `did not return to IDLE` or `CRC_STATUS changed`: stop and
  keep the output. Do not retry SENSE_CTRL or try other command codes.
- `[FAIL]`, `ERROR: write did not complete` or `VERIFY FAIL`: stop. Do not retry,
  do not burn anything else. Keep the output.
- `ffcard.py check` says STOP: do not burn. Recapture and re-derive.
- Never power-cycle between sm_hbm records. An SM unlock without the matching
  PES/ROP_L2 records fails GSP boot.

The windows can be split (for example noop; then sm_hbm; then pcie + nvlink)
with a cold boot and `ffcard.py check` between them, or all done in one.

### 7. Verify after a cold boot

Power off at the wall for about 30 s and cold boot, with the stack still disabled:

```sh
sudo setpci -s $BDF COMMAND=0x0002:0x0002
sudo python3 $C/planner/ff_dump.py --bdf $BDF --out $C/planner/card-dump-final.json
sudo python3 $C/planner/read_defects.py $BDF > $C/planner/card-defects-final.json
python3 $C/planner/ffcard.py verify --dump $C/planner/card-dump-final.json \
    --defects $C/planner/card-defects-final.json $C/burn/mycard_plan_*.json
sudo python3 $C/planner/pcie_state.py $BDF
```

`verify` passes when every record reads back, nothing else was written, the
option fields replayed from the rows and the option shadows equal the planned
targets, SYS_PIPE and the device ID are unchanged and the defect masks did not
move. It prints the first blank row for the next plan. `pcie_state.py` exits 0
when the Gen3 gates read 0, `PCIE_MAGIC_BITS_D` reads 0x00200000 and LnkCap is
16GT/s. LnkSta stays at the boot speed until the driver retrains the link.

`STATUS_OPT_TPC_GPC3/4` reading 0x1 while the fuse fields are 0 was seen on all
three cards. It is runtime state, not a fuse, and can cost 4 SMs (128 -> 124).

### 8. Driver bring-up

```sh
sudo gpu-stack enable      # then cold boot
nvidia-smi --query-gpu=name,memory.total,pcie.link.gen.current,pcie.link.width.current --format=csv
```

The fuses only make the hardware available. An 8 GB card's driver and unlocker
still have to be told about 80 GB (local memory range 0x28B) and to train
Gen4; an unlocker that hard-codes the 8 GB card's values stays at 64 GiB and
Gen1/2 (see [Observations](#observations)). NVLink also needs the board
modification, a bridge, a second card and a matching ROM.

### 9. After unlocking: benchmark and stress

Newly enabled SMs and the fifth HBM stack were disabled at the factory for a
reason on some dies, so prove them before trusting the card. Run this after
step 8, with the driver loaded and the card's cooling running (start your fan
control first). In a second terminal, watch for driver errors the whole time:

```sh
sudo dmesg -wT | grep -i xid      # any Xid (13, 31, 43, 48, 79, ...) = stop and investigate
nvidia-smi -l 2 --query-gpu=temperature.gpu,power.draw,clocks.sm,clocks.mem --format=csv
```

The tools need the NVIDIA driver (`libcuda.so.1`); `bench.cu` also needs the
CUDA toolkit to build. On a host with several GPUs, select the card with
`CUDA_VISIBLE_DEVICES=<index>` (`sm_stress.py` uses device 0; `nvidia_bench`
also takes the GPU id as its first argument).

**1. SM count and SM stress** (`bench/sm_stress.py`, Python + hand-written PTX,
no compiler):

```sh
python3 bench/sm_stress.py probe            # SM ids that received a block
python3 bench/sm_stress.py run all 600      # all SMs, 10 minutes
```

`probe` lists the SM ids that actually run work: compare the count with the
fuse result from step 7 (2 SMs per enabled TPC; e.g. 128, or 124 with the GPC3/4
runtime mask). `run` keeps every selected SM busy with dense FFMA and checks on
every launch that each one got a block; `WARNING ... no block reached` means an
SM dropped out. Exit 0 = ran to the end; a lost GPU exits 2 with the CUDA error.
To localise a failure, bisect with `lo`/`hi`, then `q0`..`q3`, then
`ids:3,7,9`.

**2. Benchmark** (`bench/bench.cu`):

```sh
nvcc -O3 -o bench/nvidia_bench bench/bench.cu -lnvidia-ml -ldl \
    -gencode arch=compute_80,code=sm_80
./bench/nvidia_bench                 # full report; ./bench/nvidia_bench 0 0 --csv for one CSV line
```

Check the report for: total memory (81920 MiB), DRAM bandwidth (should scale
with five HBM stacks, not four), the PCIe link (16GT/s x16) and H2D/D2H
bandwidth, BAR1 size, tensor-core (TF32/BF16/INT8) throughput and the measured
boost clock. Save a stock-card run first if you can, to compare. The header of
`bench.cu` has the multi-architecture build line.

**3. Memory test**: [memtest_vulkan](https://github.com/GpuZelenograd/memtest_vulkan)
(GpuZelenograd; download the Linux x86_64 build from its
[releases](https://github.com/GpuZelenograd/memtest_vulkan/releases), v0.5.0
was used; it is not bundled here):

```sh
tar xf memtest_vulkan-v0.5.0_DesktopLinux_X86_64.tar.xz
./memtest_vulkan                      # pick the NVIDIA device; let the 5-minute test finish
```

It must end with `Standard 5-minute test PASSed!` (then Ctrl+C, or leave it for a
longer soak). Any error line, a size well under 80 GB, or an Xid is a fail. On
one unlocked card it tested 75 GB per pass at about 1000 GB/s write / 600 GB/s
check and passed 1329 iterations.

All three passing (no Xid, full SM coverage, memtest PASS) is the bar for
calling a card unlocked. A die that fails on one SM or memory partition is
not repaired by these tools: disabling a unit again needs a new FF record
(a human decision, planned from a fresh dump), and every record uses a
fuse row for good.

## Plan file format

```json
{
  "mode": "sm_hbm", "card": "mycard", "order": 1,
  "records": [{"chain": 1, "block": 5, "old_data": "0x9867", "new_data": "0x8007",
               "encoded": "0x80070141", "row": 293}],
  "expect_fields": {"OPT_GPC_DISABLE": "0x0"},
  "unchanged_fields": {"OPT_PCIE_DEVIDA": "0x20C2"},
  "baseline": {"last_row": 291, "fingerprint": "0123456789abcdef"},
  "source_dump": "card-dump.json", "source_defects": "card-defects.json"
}
```

`encoded = (new_data << 16) | (block << 6) | chain`; bit 5 (IFF) is always 0. The
last record for a block wins. `ff_burn.py` reads only `row` and `encoded`.

## Field map (Kate Land's published FF map)

| Field | Chain | Bits | Field | Chain | Bits |
|---|---|---|---|---|---|
| FBIO_DISABLE | 1 | 83-106 | FBP_DISABLE | 1 | 307-318 |
| FBPA_DISABLE | 1 | 107-130 | ROP_L2_DISABLE | 1 | 319-342 |
| GPC_DISABLE | 1 | 131-138 | NVLINK_DISABLE | 1 | 368-370 |
| TPC_DISABLE_GPCi | 1 | 187+8i - 194+8i | SYS_PIPE_DISABLE | 1 | 372-379 |
| PES_DISABLE | 1 | 251-274 | PCIE_DEVIDA/B | 2 | 593-608 / 609-624 |

Block N of a chain holds bits [16N, 16N+16).

## Tests

```sh
python3 -B -m unittest discover -s tests -v
```

Synthetic dumps only: derive (field-only changes, no device-ID blocks, row
allocation, `--skip-rows`, missing defect masks, unexpected PCIe blocks),
check (resume point, another card, wrong word, stray write), verify, and the
`pcie_state.py` config-space parser. No test opens a device.

## Observations

Single-card observations, not guarantees:

- The fuses only make the fifth HBM stack available. Capacity is set in software
  by the unlock driver: LOCAL_MEMORY_RANGE 0x28B (80 GiB) and an 80 GiB GSP
  framebuffer target. Unlockers hard-coding the 8 GB card's 0x20B stay at 64 GiB.
- With an 80 GiB range, the NVIDIA registry key `RMForceStaticBar1=1` failed GSP
  initialisation (`GSP_INIT 0x3e`) on a 64 GiB BAR1; without it the card reached
  81920 MiB. The driver build changed at the same time, so the key is the likely,
  not isolated, cause.
- With the PCIe plan burned, LnkCap reads 16GT/s, but the link trains at boot
  speed until the driver/unlocker retrains it stepwise (Gen2 -> Gen3 -> Gen4).
- `STATUS_OPT_TPC_GPC3/4` read 0x1 at runtime on all three cards while the fuse
  fields were 0; the driver may report 4 SMs fewer than the fuses allow.
- Appending FF records consumes one-time-programmable rows; a later record can
  override a block, but nothing un-burns a row.

## Glitching

For faster glitching campaigns, see
[dalzyu/pico-ga100vfi](https://github.com/dalzyu/pico-ga100vfi), an RP2350/Pico 2
toolchain using PMBus voltage control and PEX_RST timing. Follow that project's
build, wiring and hardware precautions. Nothing here drives the Pico or
automates glitching.

## Credits

- **Kate Land**: published GA100 voltage-glitching research, the FF record
  format and field map, and the Goldilocks SENSE_CTRL arming sequence; see
  [SOURCES.md](SOURCES.md).
- **xPatrik (Discord)**: research contributions and reference material.
