# Public-plan FF burner

`ffburn.py3` consumes `ga100-public-ff-plan-v2` files from the adjacent
`ffplan.py3`. Python 3.8+ and the standard library are sufficient. The planner
must remain beside the burner; the burner does not use the legacy local engine,
physical-alias maps, reference toolkit scripts, GPIO routines or network access.

The implementation follows the documented main-array command sequence and adds
plan regeneration, baseline binding, repeated full-array reads, restricted MMIO
ports, post-intent prerequisite checks and durable attempt logging. It has been
validated with injected I/O, not a real GPU. A passing logical plan does not
qualify an electrical programming setup or prove a cross-die empirical mapping.

## Offline review is the default

```sh
python3 ffburn.py3 --baseline card-a-raw.json --plan card-a-plan.json
```

This command opens no hardware and creates no journal. It regenerates and replays
the exact plan against its original evidence and reports the rows, words, plan
ID and limitations. Modified plans and wrong evidence fail. Use the same
`--repeat` or `--defects` inputs used when planning, if applicable. The burner
requires two complete matching 512-row passes, including the IFF boundary;
partial-range reference toolkit captures alone are insufficient.

Existing full-conversion plans are consumed directly; no schema translation or
re-encoding is needed. Regenerate with this package's planner when an older
manifest fails exact regeneration. One combined plan gives one row allocation;
do not stack overlapping plans.

## Live preflight

On the Linux host, select exactly one card per invocation. The driver must be
unbound, PCI memory decoding already enabled, and BAR0 accessible. The tool never
unbinds drivers or changes PCI configuration. The initial PCI identity must be
NVIDIA CMP `20c2` or the supported glitch identity `2080`; the selected BDF must
match the plan. The full physical array must match the baseline exactly, not
merely the BDF or a few option words.

The programming window and any required external supply must already be
established and maintained by the operator's qualified setup. This package does
not control a Pico, reset, voltage, GPIO, rail timing, ROM, SW override or PLMs.
It checks the resulting registers rather than attempting to open them.

| Observation | Required value |
|---|---|
| FUSECTRL state bits20:16 | IDLE (4) |
| DEBUGCTRL 0x820060 | 0 (reject RIR and other debug modes) |
| CRC_STATUS 0x820070 | 0x55 |
| DSOV 0x820084 | 0 |
| EFP 0x820078 | 1 |
| SBFE 0x821108 | 0 |
| EN_SW_OVERRIDE 0x820040 | 1 |
| WDATA_WR_SECURE 0x82048c | 0 |
| FUSEWDATA_PLM / FUSECTRL_PLM | 0xffffffff |
| PMC_BOOT_0 | Accessible and nonzero |

Reserve a different journal for every operation; its parent directory must
exist. Example with a directory created by the operator:

```sh
mkdir -p journals
sudo python3 ffburn.py3 --baseline card-a-raw.json --plan card-a-plan.json \
  --bdf 0000:01:00.0 --preflight --journal journals/card-a-preflight.jsonl
```

Preflight issues only CMD_IDLE and CMD_READ/address writes. Its adapter rejects
WDATA and CMD_WRITE. It checks burn-window prerequisites before commands, reads
all 512 rows twice, compares both passes with the baseline, and restores the
original address on success. It holds the same advisory per-card lock as public
capture.py3. Other tools must not access the device concurrently; advisory locks
do not control unrelated software.

A preflight result does not authorize a later session or prove analog conditions.
Programming repeats the checks and full baseline comparison in its own session.

## Explicit programming

Pass the exact `plan_id` printed by offline review, plus a new journal:

```sh
sudo python3 ffburn.py3 --baseline card-a-raw.json --plan card-a-plan.json \
  --bdf 0000:01:00.0 --execute-plan PLAN_ID \
  --journal journals/card-a-program.jsonl
```

This command is an irreversible OTP programming request. There is no default
programming or implicit card selection. Programming requires three exact
interactive confirmations, in order:

1. The selected card's BDF.
2. The full plan ID.
3. `BURN N ROWS`, with the exact number of records replacing `N`.

Each incorrect answer, EOF or interruption aborts immediately; there is no prompt
retry or noninteractive bypass. Offline review and preflight do not prompt.
All live prerequisite checks and both full baseline passes run after the final
confirmation, with fresh per-record checks immediately before programming.
There is no retry loop, automatic resume, repair or rollback operation.

Before each record the tool syncs a program-intent event, freshly reads the
selected row as blank, checks prerequisites, stages address/data, and checks
prerequisites/address again immediately before CMD_WRITE. The sequence is
`CTRL=0 -> ADDR=row -> WDATA=word -> CTRL=2 -> poll IDLE -> CMD_READ -> verify`.
Only validated main-array FF rows 222–487 are supported. No SENSE/RIR command or
security/override register write is permitted by the adapter.

Any timeout, changed guard, wrong row/readback, interrupted command or failed
journal write stops the operation. It never reissues a program command. After
an uncertain failure it performs no cleanup MMIO, including no address restore;
the journal reports attempted and verified rows. Do not rerun or retry a failed
or partial burn: a zero readback does not establish that a cell was unaffected.
A partial array no longer matches the original baseline and is rejected by a
fresh invocation. A new capture does not make retrying a failed cell safe.

On success, two further complete raw passes must equal the original array with
only the planned words added, and the original address is restored. A journal
failure after writes can still make the process fail after records landed; keep
the journal and stop. The tool does not turn off or otherwise manage an external
programming supply on either success or failure; the external rig must provide
its own sequencing and fail-safe behavior.

Success reports only `full_array_verified` in the current session. It explicitly
leaves cold-boot replay and working features unverified. Power-cycle behavior,
matching ROM requirements, driver floorsweeping/FMA behavior, actual PCIe speed,
memory integrity, NVLink and ECC require separate validation. The A100 device-ID
feature requires a matching signed ROM; the CMP ROM alone is not functional
after conversion. Extra MAGIC_D groups remain reference-die findings requiring
per-card validation before hardware use.

The journal is exclusively created with permissions 0600 and fsyncs events plus
the initial parent directory entry. Existing journals are never overwritten or
appended. Logs contain card identifiers and observations; keep them private.
