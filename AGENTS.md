# Agent workflow: capture, plan, simulate — NEVER BURN

## Absolute boundary

**NEVER BURN FUSES. Use this repository only to capture observations, generate
plans, and simulate them. Programming is a human-only operation outside this
agent workflow. A complete plan, successful simulation, or open burn window
never authorizes an agent to program hardware.**

- Never execute `ffarm.py3 --arm` or its live arming functions against hardware.
  Offline description and synthetic tests are allowed.
- Never execute `ffburn.py3`, its live functions, another burn tool, or a custom
  replacement against hardware. Never supply or automate burn confirmations.
- The same applies to `cmp170/`: never run `cmp170/arm/*.py` or
  `cmp170/burn/ff_burn.py` against hardware. `cmp170/planner/ffcard.py` is
  offline and allowed; `ff_dump.py`, `read_defects.py` and `pcie_state.py` read
  live hardware and follow the capture rules below.
- Never issue `CMD_WRITE` (2) or `CMD_SENSE` (3), write FUSEWDATA, change software
  override/security/PLM registers, or access the RIR programming macro.
- Never glitch, reset, retrain, flash, change voltage/GPIO, unbind drivers, or
  modify PCI configuration as part of this workflow. Do not invoke an external
  glitching or programming tool.
- Do not weaken guards, invent missing evidence, default unknown defects to
  zero, or convert candidate records into automatic programming actions.
- Synthetic tests with fake I/O are allowed. Never connect tests to real devices.

## 1. Select evidence and capture

Read `README.md`, `SOURCES.md`, and the use-at-your-own-risk warning. Require the
user's intended card BDF(s); do not choose a target by GPU index or slot guessing.
Process each card separately and preserve its association with all outputs.
Record its GPU UUID too. If driver information is unavailable after unbinding,
use a previously saved BDF/UUID mapping via `--gpu-uuid BDF=GPU-UUID`. Never
invent a UUID or label a supplied mapping as live-verified.

Use a normal CMP `20c2` baseline with clean CRC for planning. Before live capture,
the selected Linux card must already be unbound, PCI memory decoding enabled,
and BAR0 accessible. Do not establish these conditions yourself. If conditions
are unmet, report the blocker and use existing captures for independent offline
work where possible. If running away from the GPU host, use the user's existing
captures; do not claim that new hardware reads occurred.

Create a fresh output directory for each card/run. The BDF below is a placeholder
and must be replaced with the selected card. Run steps separately and inspect
each exit status before continuing:

```sh
CARD_BDF='REPLACE_WITH_SELECTED_BDF'
mkdir -p runs
RUN_DIR=$(mktemp -d runs/card.XXXXXXXX)
sudo python3 capture.py3 --bdf "$CARD_BDF" --raw --output "$RUN_DIR/capture.json"
```

`--raw` is the narrow permitted MMIO exception: physical-row address selection
and `CMD_READ` only, using the existing capture adapter. It reads all 512 rows
twice, checks state/CRC/debug/address readback, and attempts address restoration.
Never replace it with direct MMIO or generic register-write commands.

Check capture success, both matching option snapshots, both matching raw passes,
clean CRC, absence of read issues, and successful address restoration. Preserve
failed/partial observations, report them, and do not plan from unreliable data.
Never overwrite an earlier capture. With existing evidence, use its original
path as the baseline in the next commands rather than copying or editing it.

## 2. Generate a per-card plan

Default scope is memory, compute, and the experimental Gen3 candidate pair.
State this scope explicitly. Only add other feature selections when requested;
review their mapping uncertainty and ROM/hardware dependencies first. Use the
explicit route: `cmp` by default, `a100` for requested identity conversion, and
`empirical` only for a requested extra MAGIC_D experiment. SYS_PIPE is opt-in.
Do not imply that it unlocks ECC or NVDEC.

```sh
python3 ffplan.py3 plan --baseline "$RUN_DIR/capture.json" \
  --features memory compute pcie-gen3-pair --output "$RUN_DIR/plan.json"
```

Use `python3 ffplan.py3 changes` to review available capabilities and their limits.
Select them using `--changes` (`--features` is an alias). Unsupported entries
must never generate records. Review `proposed_changes` in both plan and replay
outputs, including shared row references and per-field targets.

Inspect `status`, `missing_evidence`, `ff_boundary_evidence`, source hashes, `field_edits`,
`register_effects`, `records`, `dependency_checks`, `space_budget`,
`cold_boot_checkpoints`, and the IFF boundary. Account for one restoration row
per changed block, requested proof-row budget, and the software spare margin.
Proof encodings have no assigned row or selection; proof/restoration previews
allocate no executable records. Never execute a
checkpoint or claim it is bootable or cold-boot verified. Require targets to retain
reported defects and unrelated block bits. Rows must be observed trailing blanks
before the first observed record with bit5 set (`word & 0x20`). Never assume
row488 or treat eight zero rows as proof of the boundary. Require the repeated
IFF_RECORD START/LAST to be valid and START to match the raw bit5 marker. Old
captures without that register require recapture; do not synthesize the value. Never invent an IFF boundary, repeat pass, identity,
missing register, fuse location, or defect mask.

Exit 2 means incomplete evidence (or CLI usage error); inspect the diagnostic
and stop dependent work. Exit 1 means validation/I/O failure. Do not treat either
as a complete plan. Regenerate stale plans rather than modifying their JSON.

## 3. Simulate and review

Only simulate a complete plan using exactly the same baseline and any `--repeat`
or `--defects` inputs used during generation. The output directory must be fresh;
never overwrite an existing simulation result.

```sh
python3 ffplan.py3 simulate --baseline "$RUN_DIR/capture.json" \
  --plan "$RUN_DIR/plan.json" > "$RUN_DIR/simulation.json"
```

Require a zero exit status and valid result JSON. Preserve failures instead of
hiding them or labeling them successful. Manually inspect every proposed block
change, preserved bits, append row and encoded 32-bit word against the source
capture. Simulation verifies logical FF replay only: it does not prove electrical
programming conditions, cold-boot behavior, memory integrity, working SMs, PCIe
speed, ECC, NVLink, or an empirical mapping on this card.

## 4. Deliver artifacts and stop

Return the per-card paths to the capture, plan and simulation, selected features,
record count, proposed row range, validation outcomes, and unresolved findings.
Clearly state **NO FUSES WERE BURNED**. Do not proceed to programming, even after
all offline checks pass. Leave manual inspection and all hardware execution to
the human operator outside this agent workflow.

Keep captures, generated plans, simulations, journals and card identifiers out
of commits and release ZIPs. `runs/` and generated JSON/log files are ignored.
Publish only allowlisted source, documentation and synthetic tests.
