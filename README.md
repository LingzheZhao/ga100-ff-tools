# ga100-ff-tools

> **USE AT YOUR OWN RISK.** These experimental tools are provided **AS IS**, without
> warranty. Fuse programming is physically irreversible and can permanently damage
> your GPU, VRM, board, or other hardware, or cause data loss. To the extent
> permitted by applicable law, the authors and contributors accept no liability
> for damage or loss arising from use of these tools.
>
> **Manually double-check every burn plan before running it.** Verify the intended
> card and baseline, defect masks, chain/block edits, blank append rows, and encoded
> 32-bit words. Automated validation and confirmations do not replace manual review.

Public-source GA100/CMP 170HX fuse capture, per-card FF planning, replay
simulation, and guarded programming tools.

Standalone capture/planning tools for Python 3.8+, using public register references and
published FF mappings and explicitly labeled supplied research findings.
All register constants are embedded. The standard library
is sufficient; no NVIDIA headers, register JSON files, original project folders,
network access or Python packages are required at runtime. An optional offline
reference-source validator is also included; it uses the adjacent primary scripts.

- `capture.py3`: Linux option/status capture, with optional physical-row reads.
- `ffplan.py3`: offline per-card planning and logical FF replay simulation.
- `ffburn.py3`: optional public-plan burner; offline review by default, explicit
  Linux programming opt-in. Requires the adjacent planner and three interactive confirmations before programming;
  see [BURNER.md](BURNER.md).
- `validate_reference.py3`: optional independent source/plan audit against a
  separately supplied trusted reference tools.

Public references are documented in [SOURCES.md](SOURCES.md). This directory
contains no real-card captures, identifiers, calibration profiles, ROMs or
generated plans. Tests build their own synthetic fixtures in temporary folders.

## Agent workflow

[AGENTS.md](AGENTS.md) instructs coding agents to capture, generate per-card
plans, and simulate them, then stop. **Agents must NEVER BURN fuses**, invoke the
live burner, or automate its confirmations. Generated records require manual
review; successful checks are not programming authorization.

## Capture

On the Linux GPU host, identify the intended card with `lspci -Dnn -d 10de:`.
The target must be unbound from its driver with PCI memory decoding already
enabled. Capture requires permission to access its PCI sysfs files, normally root.
The tool verifies the selected PCI identity and takes an advisory per-device
lock. Other tools and drivers must stay away from the target during capture.

For a complete planner input:

Each dump records `gpu_uuid` and `gpu_uuid_observation` (source and whether a
live per-BDF driver lookup verified it). The UUID is read from
`/proc/driver/nvidia/gpus/<BDF>/information` when available. Before unbinding,
save the BDF/UUID association using `nvidia-smi --query-gpu=pci.bus_id,uuid --format=csv,noheader`.
After unbinding, provide that saved association explicitly:

```sh
sudo python3 capture.py3 --bdf 0000:01:00.0 --raw \
  --gpu-uuid 0000:01:00.0=GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --output card-a.json
```

Replace the placeholder with the card's full UUID. Repeat `--gpu-uuid BDF=GPU-…`
for multiple cards. Supplied UUIDs are labeled as user-provided when the driver
lookup is unavailable; a conflicting live UUID aborts capture before BAR access.
Missing UUIDs are explicitly recorded as unavailable, never guessed. The planner
already carries this UUID into its specimen metadata.

```sh
sudo python3 capture.py3 --bdf 0000:01:00.0 --raw --output card-a.json
```

For several explicitly selected cards, captured sequentially:

```sh
sudo python3 capture.py3 --bdf 0000:01:00.0 0000:02:00.0 --raw --output-dir captures
```

Default mode omits physical-row reads and uses a read-only BAR0 mapping:

```sh
sudo python3 capture.py3 --bdf 0000:01:00.0 --output options-only.json
```

`--raw` explicitly enables a narrow MMIO write path: select a physical row and
issue CMD_READ. It reads all 512 rows twice, checks controller/CRC/debug state,
checks address readback, bounds elapsed time and attempts to restore the prior
address. Partial observations survive a failure. It never issues programming,
re-sense, override, reset or voltage commands. It does not modify PCI config.
Program/data and unrelated MMIO write ports are rejected by the adapter.

Option snapshots bracket the raw reads. Errors, mismatching passes and address
restoration failures make the capture unsuccessful. Exit status is nonzero when
any card fails; one failed card does not prevent capture of the other selected
cards. Existing output files are never overwritten. A process or machine failure
can prevent software cleanup; the prior address is not guaranteed restored then.

Inspect the embedded public register list offline:

```sh
python3 capture.py3 --list-registers
```

The raw capture provides all public defect option registers needed by the planner,
so a separate defect snapshot is unnecessary for this workflow. Captures with a
glitched `2080` identity can be recorded, but planning requires a normal `20c2`
capture and clean CRC. No real hardware was accessed to validate this release.

## Plan and simulate

These commands run offline, on Linux, macOS or Windows:

```sh
python3 ffplan.py3 plan --baseline card-a.json --output card-a-plan.json
python3 ffplan.py3 simulate --baseline card-a.json --plan card-a-plan.json
python3 ffplan.py3 public
```

Each card needs its own capture and regenerated plan. Input-file hashes and
captured-row fingerprints bind plans to the selected evidence; BDF alone is not
treated as card identity. Missing defect values remain unknown, never zero.
Provided chain summaries and blank-row lists are not trusted: the planner
reconstructs records from observed words, terminates FF interpretation at the
first IFF marker and allocates after the latest occupied FF row. It preserves
unrelated block bits and retains reported defective units.

`field_edits` explains proposed mask changes; `records` contains experimental
append-row candidates. A complete logical plan is not programming authorization.
The optional burner consumes this schema; its use is documented in [BURNER.md](BURNER.md). Memory geometry, working SM counts, full-capacity
memory correctness, PCIe negotiation and electrical programming conditions are
not established by logical replay.

`--features pcie-known` is a separate experimental selection for known speed/boot
flags. It excludes the ambiguous Gen3 field in chain-2 block 39;
it does not establish working Gen4. The default plan selects memory, compute and the experimental Gen3 candidate pair.
An explicit `--features` list replaces these defaults; use `--features memory compute`
to omit the pair.

To add only the published `NV_FUSE_OPT_PCIE_MAGIC_BITS_D[25]` restriction to a
combined memory/compute plan:

```sh
python3 ffplan.py3 plan --baseline card-a.json --features memory compute pcie-gen4-bit25 --output card-a-combined-plan.json
python3 ffplan.py3 simulate --baseline card-a.json --plan card-a-combined-plan.json
```

The option's register offset is `0x00820520`, bit mask `0x02000000`; its published
FF location is chain 2, block 47, bit 3. `field_edits` and `register_effects` name
that exact bit and show the modeled before/after register word. Simulation checks
that the bit clears and other register bits remain unchanged. Only FF block bit 3
is changed for this feature; additional MAGIC_D flags and Gen3 remain untouched.
Clearing this restriction alone does not establish working Gen4 or train the link.
Use one combined plan so features share a single physical-row allocation.


### Experimental Gen3 pair

`--features pcie-gen3-pair` explicitly clears chain 2, block 39, **data bits 1
and 9** (mask `0x0202`). The supplied research reports `0x0782 -> 0x0580` followed by
`NV_FUSE_OPT_DISABLE_GEN3_SPEED` (`0x820250`) reading zero. Its derivation script
explicitly leaves the individual controlling bit unresolved. The planner models
the combined FF edit, preserves all other block bits, and does not predict the
speed-disable shadow or establish working Gen3. Required evidence includes the
observed original block, IFF boundary and repeated speed-disable shadow.

This option incorporates the supplied experimental findings; it is not
attributed to Kate's published bit map. Plans selecting it carry
`public_sources_only: false` and explicit experimental evidence metadata, even
though this package contains no proprietary maps or driver code.

For one combined memory/compute, Gen3 pair, known boot gates and Gen4-bit25 plan:

```sh
python3 ffplan.py3 plan --baseline card-a.json --features memory compute pcie-gen3-pair pcie-known --output card-a-combined-plan.json
python3 ffplan.py3 simulate --baseline card-a.json --plan card-a-combined-plan.json
```

Use one regenerated combined plan instead of stacking separate plans. The
`pcie-known` selection includes the two block-49 boot gates and block-47 bit3;
it does not clear additional MAGIC_D flags in blocks 46/47. Link initialization
and training remain separate from logical FF replay.

## Additional burn-record findings

The supplied reference burn record is incorporated as per-card planning policies;
its row numbers and defect masks are never copied into a target card. Default
features remain `memory compute pcie-gen3-pair`. These additions require explicit
selection:

| Feature | Proposed change | Limits |
|---|---|---|
| `pcie-gen4-completion` | Clear block46 bit13; block47 bits0,4,6 and the known bit3. | One-die empirical map; verify with a per-card volatile test before hardware use. Individual mapping of bits0,4,6 to MAGIC_D bits22,26,28 is unknown. |
| `nvlink` | Chain1 block23 bits0–2 to captured NVLINK_DEFECTIVE. | Other block bits, including SYS_PIPE unless selected separately, preserved; never assumes no defective links. Hardware/ROM work needed; bring-up untested. |
| `sys-pipe` | Chain1 bits372–379, block23 bits4–11, to captured SYS_PIPE_DEFECTIVE. | Optional; preserves bit3 and NVLink bits. MIG enumeration reported on a reference die; ECC/NVDEC/media operation unproven. |
| `a100-device-id` | DEVIDA/B `0x20c2 -> 0x20b5` through chain2 blocks37/38. | Preserves adjacent bits; adds required bits to fresh FF replacement records. Requires a matching signed A100 ROM; CMP ROM alone is not functional after conversion. |

Capture now includes public `NV_FUSE_OPT_NVLINK_DEFECTIVE` at `0x82068c`. Old
captures lacking it give incomplete NVLink plans, never a zero target.

Choose the intended route explicitly. `--route cmp` (default) keeps the CMP
identity and rejects device-ID changes. `--route a100` permits a requested
`a100-device-id` feature and preserves the additional MAGIC_D groups. The route
does not automatically select features. A100-ROM Gen4 operation has been
reported with MAGIC_D `0x14680000`; `0x00200000` is not a universal requirement.

An A100-route preview, retaining the unknown SYS_PIPE/media behavior by default:

```sh
python3 ffplan.py3 plan --baseline card-a.json --route a100 --features memory compute pcie-gen3-pair pcie-known nvlink a100-device-id --proof-rows 2 --output conversion-preview.json
python3 ffplan.py3 simulate --baseline card-a.json --plan conversion-preview.json
```

Only use `--route empirical` with an explicit `pcie-gen4-completion` selection
to preview the extra MAGIC_D experiment. The A100 route rejects that selection;
it is never silently added. `sys-pipe` is a separate explicit feature and is not
implied by NVLink, identity conversion, or either route.

The empirical Gen4 model checks that each observed FF group and its shadow group agree
with the reference pattern (all set or all clear); unsupported partial groups
are rejected. It merges overlapping Gen4 edits into one record per block. With
the reference starting word, sequential `register_effects` end at MAGIC_D
`0x00200000`, preserving unrelated bits. This is a logical prediction, not
verification of the mapping on the selected card. Plans explicitly retain
`hardware_mapping_verified_on_this_card: false` and require per-card volatile
validation. `public_sources_only` is false for experimental Gen3, Gen4 completion
or device-ID/SYS_PIPE policies; this denotes supplied research provenance, not proprietary
code. The planner performs no live probe, burn, ROM flashing or device reconfiguration.
The separate burner requires explicit execution and an externally prepared setup.

The planner keeps PES in compute and ROP_L2 in memory; the default combined
selection covers the reported GSP boot failure from incomplete floorsweeping.
Compute selections now require the final logical PES and ROP/L2 masks to match
their captured defect masks. A compute-only plan with unresolved ROP/L2 produces
an incomplete preview with no records; include `memory compute`, or supply a
baseline where ROP/L2 already matches its defect mask.
Native versus override SM counts and FMA speed are die/driver dependent;
reference-die counts such as 124/128 are not universal targets. No ECC fuse or SM_SPEED throttle change is
planned. ECC, NVLink, memory integrity and working link speed are not proven by
FF replay. `conversion_findings` embeds these limits in generated plans.
Appending restoration records consumes permanent OTP space; it does not undo
physical fuse programming. This package does not add a live restore operation.

## Other capture formats and incomplete evidence

The planner also accepts earlier two-pass `raw_rows` captures and
indexed `rows`/`ff_rows` objects from reference tools. For a single-pass dump:

```sh
python3 ffplan.py3 plan --baseline ff-first.json --repeat ff-second.json --defects defects.json --output preview.json
```

Repeated captures must agree. Separate defect snapshots must be complete and
repeatable, match overlapping evidence and be associated with the same card.
Redacted UUIDs and matching BDFs alone do not establish that association.
Missing PES/ROP fields, an unobserved IFF boundary or unclassified reserved-chain
records leave the plan incomplete. They are never silently filled or skipped.

Planner exit codes:

| Code | Meaning |
|---|---|
| `0` | Requested offline operation completed; a plan may contain no changes. |
| `1` | Invalid input, failed validation or an I/O error. |
| `2` | Incomplete planning evidence, with no proposed records; also CLI usage errors. |

An incomplete preview lists `missing_evidence` in its JSON. It cannot be simulated
as a complete plan. Old manifests must be regenerated after planner/schema changes.
Source-generation scripts and captured hardware data are not included here.

## FF/IFF boundary: record bit 5

The planner starts FF interpretation at row222 and stops at the **first observed
raw record with bit5 set** (`word & 0x20 != 0`). That row and all later rows are
excluded from FF decoding and append allocation; its payload or chain bits do
not make it an FF replacement. The boundary is observed per capture, not assumed
to be row488. Eight blank rows do not establish an IFF boundary in this model.

Raw captures report `ff_boundary_observation`. Plans report
`ff_boundary_evidence`: the marker row/word, last occupied FF row, trailing blank
capacity, planned remaining capacity, and the 16-row software reserve. An early
marker, for example at row310, reduces available append space; insufficient
space rejects planning. Missing boundaries leave plans incomplete, while
ambiguous all-ones/PRI-like words are never guessed past.

Capture reads `IFF_RECORD` at `0x820050` in both option snapshots. The planner
extracts START `[8:0]` and inclusive LAST `[24:16]`, validates
`222 <= START <= LAST < 512`, and requires START to equal the raw bit5 boundary.
Contradictory ranges/markers fail validation. Missing repeated IFF_RECORD evidence
leaves the plan incomplete with no records; **old captures require recapture**.
The register is a writable current execution range, not immutable geometry.
`iff_register_checked: true` records agreement, not hardware qualification.

The type-bit model, register cross-check and spare-row policy do not establish
programming eligibility. Regenerate older plans after this specification update.
Manually inspect the boundary before any hardware operation; agents must never burn.

## Proof, restoration and checkpoint previews

`space_budget` counts functional records, one reserved restoration row per changed
block, the requested `--proof-rows N` (default zero), and 16 additional spare rows.
Insufficient total capacity rejects a complete plan. `remaining_blank_rows_after_plan`
is the physical space after functional records; the stricter
`remaining_after_all_reservations` subtracts restoration, proof and spare budgets.
These reservations do not allocate, occupy or program rows.

`proof_preview` records the requested budget and, for complete evidence, lists
unallocated no-op encoding candidates from declared blocks untouched by the
functional plan. Each duplicates its observed current value and verifies unchanged
logical replay, but has `row: null`, no chosen candidate or execution order, and
`physical_no_op_established: false`. Incomplete evidence withholds candidates.
A no-op is still an irreversible write; select and allocate it only through
independent human review and fresh evidence. `restoration_preview` lists the
original block values but deliberately allocates no executable restore records.
A real restoration requires fresh post-change evidence and consumes more OTP.

`cold_boot_checkpoints` and simulation results show one logical prefix per record,
with the current PES/ROP dependency state. They never claim an intermediate state
boots, that a cold boot occurred, or that a stage works. Intermediate floorsweep
states may be incomplete. They are not execution/resume manifests: after an
actual hardware change, the old baseline/remaining plan is stale and fresh
capture and planning are required. Agents must never execute these checkpoints.

SYS_PIPE changes do not identify the separate NVDEC fuse. Neither matching option
words nor a failed whole-block ECC match proves a complete map or functional ECC.
No new ECC, NVDEC, SM_SPEED, SKU_ID, ROM or InfoROM operations are implemented.

## Faster glitching with Pico 2

For faster glitching campaigns, see
[dalzyu/pico-ga100vfi](https://github.com/dalzyu/pico-ga100vfi). It provides an
RP2350/Pico 2 toolchain using PMBus voltage control and PEX_RST timing. Upstream
reports approximately **5.5 attempts per second without trace dumps** on its
single tested card; attempt rates and successful settings depend on the board
and setup. Follow that project's build, wiring, and hardware precautions.

That project handles the glitching step. This repository does not drive the Pico
or automate glitching; the burner independently checks the live programming
prerequisites and baseline. Manually review the per-card plan before execution.

## Public-plan burner

Offline review opens no hardware:

```sh
python3 ffburn.py3 --baseline card-a-raw.json --plan card-a-plan.json
```

See [BURNER.md](BURNER.md) for live preflight, exact-plan execution, required
external preparation, durable journals and failure behavior. No hardware setup,
voltage, override, reset, ROM flashing or retry is automated.

## Reference-source validation

See [AUDIT.md](AUDIT.md) for the complete source review, confirmed software
agreement, defects in the reference tools, and reproducible offline validation.
The public capture and optional burner reject nonzero DEBUGCTRL before row
commands. Card-specific audit outputs are not bundled; live burner usage and
limits are documented separately in [BURNER.md](BURNER.md).

## Tests

```sh
python3 -B -m unittest discover -s tests -v
```

Tests exercise the capture-to-plan pipeline, read-only mapping, command-write
restrictions, deadlines, partial reads, restoration failures, required defect
evidence, cross-card rejection, default Gen3 pair selection, experimental pair preservation and FF replay. All use
ordinary files or in-memory adapters. They do not qualify hardware operation.


The programming path requires three exact interactive confirmations (card BDF,
full plan ID, and `BURN N ROWS`). All live guards and baseline reads follow the
prompts. Regenerate plans after planner metadata changes; source hashes and
plan IDs bind each plan to its current evidence and specification.

## Credits

- **xPatrik (Discord)** — research contributions and reference material.
- **Kate Land** — published GA100 voltage-glitching research, FF mappings and
  public register references; see [SOURCES.md](SOURCES.md).

## Capability change list

List selectable changes and unsupported capabilities without a capture:

```sh
python3 ffplan.py3 changes
```

Select the desired changes when planning (`--features` remains an alias):

```sh
python3 ffplan.py3 plan --baseline card-a.json \
  --changes memory compute pcie-gen3-pair pcie-known --output card-a-plan.json
python3 ffplan.py3 simulate --baseline card-a.json --plan card-a-plan.json
```

The catalog includes HBM capacity, compute units, PCIe gates, NVLink, optional
SYS_PIPE/MIG, A100 identity and the separate empirical MAGIC_D experiment.
It lists ECC, NVDEC and SM-speed burning as unsupported and prevents selecting
them. Existing route requirements and per-card defect/dependency checks remain
mandatory. Explicit selections replace the default memory/compute/Gen3 set;
no extra capability is silently added.

Both outputs contain `proposed_changes`: a list of selected capabilities with
mapping status, requirements/limits, before/target field values, affected row
references and a count including shared records. Shared blocks are merged into
one final record; per-capability row counts must not be added together. The
plan's `space_budget` gives unique totals and proof/restoration reservations.
Simulation adds replayed values and target-match results. Incomplete plans list
changes as incomplete with no executable rows. A successful replay establishes
only the logical masks, never working capacity, compute, PCIe speed or other
hardware functionality. Regenerate existing plans after updating the tool;
manual edits to this list are rejected by simulation and plan validation.
