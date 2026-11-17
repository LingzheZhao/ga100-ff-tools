# CMPGlitch source audit

The review covered all 16 Python tools in the supplied CMPGlitch `tools/`
checkout and its reference `ff.json`. This public report contains no user dumps,
card identifiers, generated plans, local paths or proprietary fuse maps.
CMPGlitch source files are not bundled. No live tool was run.

## Confirmed software agreement

The capture/planner offsets, floorsweep and PES/ROP field ranges, NVLink low-three
bits, shifted 16-bit device IDs, Gen3 candidate pair and PCIe boot gates agree
with CMPGlitch's declarations. Offline validation of the user's three combined
plans found no record discrepancies. The validator independently checks physical
row decoding, field targets, defect retention, untouched bits, append rows, IFF
boundary, record encoding, hashes and saved simulation results.

This is agreement between software and supplied observations, not proof of the
underlying mappings. Gen3 bits 1/9 remain a pair, and block47 bits0/4/6 remain a
group. Additional MAGIC_D mappings are one-die empirical findings requiring
per-card volatile validation before hardware use. No working link, NVLink, ECC,
ROM compatibility or compute/memory integrity is established.

## Source defects and limits

| Tools | Findings |
|---|---|
| `ff_dump.py` | Bad CRC/non-IDLE only warns; failed reads can still exit successfully. PRI responses can decode as FF. IFF is skipped rather than terminating replay. Its default range omits the IFF boundary at row488. |
| `ff_derive.py` | Missing defects default to zero in both derivation and verification, yielding false success. Chain/blank summaries and snapshot/card association are trusted. |
| `ff_derive_pes.py` | Field ranges agree, but targets are fixed to its reference specimen and the input is a prior plan overlay. |
| `ff_derive_pcie.py` | Masks agree; individual Gen3 identity is explicitly unresolved. Row selection trusts the input's blank list. |
| `ff_derive_nvlink.py` | Field and SYS_PIPE preservation agree. Defect mask defaults to zero and out-of-width input is truncated rather than rejected. |
| `ff_magic_derive.py` | Scanner skips failed reads, ignores IFF, defaults missing block data to zero and may choose a blank preceding a later overriding record. It does not prove a fixed cross-die mapping. |
| `ff_burn.py` | No baseline/card binding or FF encoding/type validation. Guards precede an interactive prompt and are not fully repeated immediately before programming. |
| `ff_restore.py` | Restores the supplied plan's old values, not necessarily all passes. Repeated blocks can restore intermediate values; validation covers only a floorsweep subset and skips absent shadows. |
| `sw_override.py` | Volatile write/readback; DSOV is observed, not enforced, and read-only mode still maps writable. |
| `open_wdata_plm.py` | Documented SW/DSOV prerequisites are not enforced before its volatile write. |
| `pcie_gen4_fuse_test.py` | Tests a volatile whole-word shadow override, not permanent FF mapping. Masks DSOV to bit0 and can return success when the write does not stick. |
| `pcie_gen4_probe.py` | Volatile PHY work is separate from FF. Failed write-verification booleans are ignored; a training failure may still exit zero. |
| `pcie_phy_probe.py` | Read-only inspection, but does not validate identity/PRI responses. No live probe was run. |
| `pcie_phy_enable.py` | Reversed MAX_RATE mapping is correct in code despite stale introductory text. Failed write checks are ignored; whole config-space writes can replace unrelated bits. |
| `pcie_bandwidth.py` | Selects CUDA device0 without BDF binding. Throughput is not a data-integrity or ECC test. |
| `final_check.py` | Can return success with BAR, runtime and dmesg unavailable. Uses GPU0 regardless of selected BDF, uses CUDA core count as SM count in its NVML fallback, and mishandles multiple nvidia-smi rows. Hardcoded defect-free targets are not portable. Only checks MAGIC_D[25] and accepts x4 width. |

Synthetic, isolated-function reproductions confirm the missing-defect false
verification, PRI decoding, post-IFF replay, incomplete MAGIC scan, and
`final_check.py` unavailable-data false success. Live entrypoints, BAR classes,
CUDA calls, programming and retraining were not executed.

## Public tool behavior

`capture.py3` already rejects nonzero DEBUGCTRL at 0x820060 before raw reads and
before each row. RIR/debug modes are never cleared automatically. Option-only
capture remains a read-only observation. The planner rejects missing defects,
uses repeated captures, reconstructs rows, stops at IFF, preserves unrelated bits
and regenerates saved plans exactly. The planner itself performs no MMIO.

The separate legacy local burner received a matching DEBUGCTRL=0 guard during
this audit. That burner is not included in this public package and does not
accept the public planner schema. The separate original public burner now
consumes that schema; see [BURNER.md](BURNER.md). It incorporates the audit guards
and logging with explicit execution. No legacy private physical-alias map,
override helper or PHY writer is bundled. Hardware qualification remains absent.

## Reproduce offline

The optional `validate_cmpglitch.py3` needs this package's adjacent planner and
capture scripts, a separately obtained trusted CMPGlitch `tools/` checkout, and
your own captures and saved full-conversion previews. It performs no network
fetch and opens no hardware. Unlike the two primary standalone scripts, this
validator intentionally uses the adjacent scripts as declarations.

```sh
python3 validate_cmpglitch.py3 \
  --tools /path/to/CMPGlitch/tools \
  --plans /path/to/plans \
  --dumps /path/to/captures \
  --output validation.json
```

Files must be named `PREFIX-plan.json`, `PREFIX-simulation.json` and
`PREFIX-raw.json`. Prefixes are discovered from plans, or use `--cards card-a
card-b`. The validator currently covers the full conversion feature set:
`memory compute pcie-gen3-pair pcie-known pcie-gen4-completion nvlink
a100-device-id`. It is not a general validator for every partial-feature plan or
capture schema. JSON outputs contain local filenames, source hashes, BDFs and
plan identifiers; review them before publishing. Outputs are exclusively created.
