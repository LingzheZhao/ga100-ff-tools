# ga100-ff-tools

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

## Capture

On the Linux GPU host, identify the intended card with `lspci -Dnn -d 10de:`.
The target must be unbound from its driver with PCI memory decoding already
enabled. Capture requires permission to access its PCI sysfs files, normally root.
The tool verifies the selected PCI identity and takes an advisory per-device
lock. Other tools and drivers must stay away from the target during capture.

For a complete planner input:

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
| `nvlink` | Chain1 block23 bits0–2 to captured NVLINK_DEFECTIVE. | Other block bits, including SYS_PIPE, preserved; never assumes no defective links. Hardware/ROM work needed; bring-up untested. |
| `a100-device-id` | DEVIDA/B `0x20c2 -> 0x20b5` through chain2 blocks37/38. | Preserves adjacent bits; adds required bits to fresh FF replacement records. Requires a matching signed A100 ROM; CMP ROM alone is not functional after conversion. |

Capture now includes public `NV_FUSE_OPT_NVLINK_DEFECTIVE` at `0x82068c`. Old
captures lacking it give incomplete NVLink plans, never a zero target.

For a full offline preview including all six reference passes:

```sh
python3 ffplan.py3 plan --baseline card-a.json --features memory compute pcie-gen3-pair pcie-known pcie-gen4-completion nvlink a100-device-id --output conversion-preview.json
python3 ffplan.py3 simulate --baseline card-a.json --plan conversion-preview.json
```

The Gen4 model checks that each observed FF group and its shadow group agree
with the reference pattern (all set or all clear); unsupported partial groups
are rejected. It merges overlapping Gen4 edits into one record per block. With
the reference starting word, sequential `register_effects` end at MAGIC_D
`0x00200000`, preserving unrelated bits. This is a logical prediction, not
verification of the mapping on the selected card. Plans explicitly retain
`hardware_mapping_verified_on_this_card: false` and require per-card volatile
validation. `public_sources_only` is false for experimental Gen3, Gen4 completion
or device-ID policies; this denotes supplied research provenance, not proprietary
code. The planner performs no live probe, burn, ROM flashing or device reconfiguration.
The separate burner requires explicit execution and an externally prepared setup.

The planner keeps PES in compute and ROP_L2 in memory; the default combined
selection covers the reported GSP boot failure from incomplete floorsweeping.
The reference's 128 SM and full FMA speed require driver overrides; an A100 ROM
alone reportedly exposes 124 SM. No ECC fuse or SM_SPEED throttle change is
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
