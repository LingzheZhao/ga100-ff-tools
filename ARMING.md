# Experimental volatile arming

`ffarm.py3` establishes the register prerequisites after a successful glitch.
It requires the adjacent `ffburn.py3`, Python 3.8+, and the standard library.
Use at your own risk; see the package warning in README.md. This tool has been
tested with synthetic I/O only; the sequence it implements has been observed on
one card (see Hardware observation). Hardware execution is human-only under AGENTS.md.

Goldilocks can have CRC=0x55, DSOV=0 and SBFE=0 while EFP=0 and
FUSEWDATA_PLM=0xffffff8f. This is not burn-ready. The reported method issues
SENSE_CTRL to restore EFP from the physical control fuses while DSOV stays zero.
Sensing can restore SBFE=1, so the tool subsequently enables software override,
clears SBFE, and clears WDATA_WR_SECURE to open the WDATA privilege mask.
Preserving DSOV is an empirical observation, checked on every invocation,
not a hardware guarantee. EFP is never written directly.

Offline description (default; no device opened):

```sh
python3 ffarm.py3
```

Human-operated setup on Linux, replacing the placeholder with the selected card:

```sh
CARD_BDF='REPLACE_WITH_SELECTED_BDF'
sudo python3 ffarm.py3 --arm --bdf "$CARD_BDF" --journal journals/arm-unique.jsonl
```

Create the journal parent directory beforehand. The journal must be new; writes
are preceded by fsynced intent entries. The card must already be unbound, have
PCI memory decoding enabled, and be accessible through BAR0. The tool shares
the capture/burner's per-BDF advisory lock; unrelated software must stay away.
It does not glitch, reset, control supplies, unbind a driver, or alter PCI config.

The arming adapter permits only these exact writes:

| Register | Value | Purpose |
|---|---|---|
| FUSECTRL 0x820000 | 3 | SENSE_CTRL, only when EFP=0 |
| EN_SW_OVERRIDE 0x820040 | 1 | Enable shadow overrides |
| SBFE 0x821108 | 0 | Clear secured-burn restriction |
| WDATA_WR_SECURE 0x82048c | 0 | Open FUSEWDATA_PLM |

Initial guards require IDLE, DEBUGCTRL=0, CRC=0x55, DSOV=0, accessible
PMC_BOOT_0, and open controller/option PLMs. Sensing has a one-second timeout;
EFP must then be 1 and DSOV must remain 0. Every shadow write has readback
verification. Final verification requires all existing burner register guards,
including SBFE=0 and WDATA_PLM=0xffffffff. An already enabled EFP skips sensing.

Failures stop without retries or cleanup register writes. Partial shadow changes
can remain; inspect the journal and current state before further human action.
Success means register prerequisites were verified in this session, not that
the electrical setup, card identity against a baseline, or plan was qualified.
No row/data writes or CMD_WRITE are permitted. No fuses are burned by this tool.

Run the existing burner's separate baseline-bound preflight afterward, following
BURNER.md. Arming never starts programming or bypasses the three confirmations.

Sensing also requires RESENSE_DISABLE (0x821058) to read 0 before the intent is
journaled and again before the write. It is part of every snapshot.

## Hardware observation (one card, 2026-11-19)

One CMP 170HX 8 GB (Hynix, 10de:20c2) after an RP2350 I2C + PEX_RST glitch,
armed by a separate single-purpose script rather than `ffarm.py3`. That script
enabled software override and opened WDATA (WDATA_WR_SECURE=0) before sensing,
then set FUSEWDATA=0 as a no-burn latch and issued FUSECTRL=0 then FUSECTRL=3.

| Register | Before sense | After sense |
|---|---|---|
| FUSECTRL | 0xE0040000 (IDLE) | 0xE0040000 (IDLE) |
| CRC_STATUS | 0x55 | 0x55 |
| DSOV | 0 | 0 (preserved) |
| EFP | 0 | **1** |
| SBFE | 0 | **1** (restored, as expected) |
| RESENSE_DISABLE | 0 | **1** (one sense per window) |
| DISABLE_FUSE_PROGRAM | 0 | 0 |
| EN_SW_OVERRIDE | 1 | 1 (not reset by the sense) |
| WDATA_WR_SECURE | 0 | 0 (not reset by the sense) |
| FUSEWDATA_PLM / FUSECTRL_PLM / FUSEOPT_PLM | 0xFFFFFFFF | 0xFFFFFFFF |

The SBFE shadow write (with EN_SW_OVERRIDE=1) read back 0. All burner register
guards then passed, and thirteen main-array FF records were programmed and read
back exactly in that window and the next; option shadows matched the plan after
a cold boot. Before arming, the burner's dry run failed only on EFP=0, which is
the Goldilocks state described above.

This confirms the documented EFP/DSOV behavior and that FUSECTRL command 3 is
SENSE_CTRL on this die. It does not show that `ffarm.py3`'s write order works on
hardware (shadows after sensing rather than before), that other dies behave the
same, or what a second sense does once RESENSE_DISABLE=1 (not attempted).

Source: [Kate Land, Goldilock's glitch](https://blog.kate.land/posts/using-voltage-glitching-to-unlock-the-a100/#3-goldilocks-glitch),
checked 2026-11-19. This documents the EFP/DSOV behavior and shadow setup sequence.
