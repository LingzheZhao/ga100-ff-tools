# Agent rules: plan and verify, NEVER BURN

## Absolute boundary

**NEVER BURN FUSES.** Agents may derive plans and verify dumps. Every hardware
write is a human-only operation. A complete plan, a passing check or an open
burn window never authorizes an agent to program hardware, even when asked.

- Never run `burn/ff_burn.py` against hardware, with or without `--confirm`,
  and never type, pipe or automate its BURN confirmation.
- Never run `arm/sw_override.py`, `arm/open_wdata_plm.py` or
  `arm/arm_sense_ctrl.py` against hardware (not even `--read-only`: hand the
  command to the human instead). Never type SENSE for it.
- Never write or replace a burn tool, and never issue `CMD_WRITE` (2) or
  `CMD_SENSE` (3), write FUSEWDATA/FUSEADDR, or change software override,
  security, PLM or SBFE registers by any other means.
- Never glitch, reset, power-cycle, flash a ROM or InfoROM, change voltage/GPIO,
  unbind drivers, change PCI configuration or run `host/gpu-stack.sh enable|disable`.
- Never plan or burn chain 2 blocks 37/38 (PCIe device ID).
- Never edit a plan's JSON by hand. A wrong or stale plan is regenerated with
  `planner/ffcard.py derive` from a fresh dump.
- Do not weaken guards or assertions, invent missing evidence, or treat an
  unknown defect mask as zero.

Allowed: `planner/ffcard.py` (offline), reading JSON the human supplies, and
tests with synthetic data. The live readers (`planner/ff_dump.py`,
`planner/read_defects.py`, `planner/pcie_state.py`) are the human's to run unless
they explicitly ask the agent to; prefer handing over the command and checking
the pasted output.

## Double verification

Every plan is verified twice, by two independent methods, before it is handed
to the human. Every burn result is verified twice afterwards. Report both
results; if they disagree, or either fails, stop.

### Before burning: the plan

1. **Tool check.** `ffcard.py derive` must finish without REFUSED or an
   assertion, print `OK` for every field and `unchanged` for SYS_PIPE and the
   device IDs, and show no `SETS` marker.
2. **Independent check.** Do not trust step 1's output. Recompute from the stock
   dump and defects JSON yourself, without importing `ffcard.py`:
   - decode each record: `chain = w & 0x1F`, `bit5 = 0`, `block = (w >> 6) & 0x3FF`,
     `data = w >> 16`; it must equal the record's `chain`/`block`/`new_data`;
   - `old_data` must equal that block in the dump's chains;
   - `old_data ^ new_data` may only touch bits of the target fields
     (field map in README.md);
   - replay dump rows + plan records in row order (last record per block wins)
     and confirm each field equals its defect mask, and SYS_PIPE and DEVIDA/B
     are unchanged;
   - rows: the first plan row is the first blank after the last used row
     (plus `--skip-rows`), rows are consecutive, all inside 222-487 and blank in
     the dump; no block is (2, 37) or (2, 38).
3. Confirm the dump belongs to the card the human named, and that each
   plan's `baseline.fingerprint` matches `ffcard.py fingerprint` of that dump.
   A plan made for another card, even at the same BDF, must not be used.

Hand over the plans with a table of index, row and encoded word, so the human
can compare each `target:` line before typing BURN.

### In the window (human runs, agent checks)

`ffcard.py check` on the fresh window dump must report the baseline rows
matching and give the next record. Check the pasted output yourself too: rows
222..last unchanged, plan rows blank or already holding their own record, CRC
0x55, idle, no read errors. Any STOP: tell the human not to burn.

### After burning: the result

1. **Tool check.** `ffcard.py verify` on the post-cold-boot dump and defects
   must print `VERIFY PASS`; `pcie_state.py` (when the PCIe plan was burned)
   must exit 0.
2. **Independent check.** Compare every plan row with the dump's raw word
   yourself, confirm rows 222..last are unchanged and every row after the last
   plan row is blank, and compare the shadows (`OPT_*_DISABLE`) and defect
   masks with the targets.

Report the per-card result, the first blank row, and anything unresolved.
State clearly that **no fuses were burned by the agent**.

## Data hygiene

Card dumps, defects, plans, window dumps and card identifiers (UUIDs, serials,
row fingerprints of real cards) stay out of commits. `*.json` is ignored.
Tests build synthetic data only and never open a device.
