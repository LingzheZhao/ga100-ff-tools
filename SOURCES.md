# Public sources and scope

The implementation is original Python code. Register names, numeric addresses,
FF formats and empirical mapping facts were checked against these public primary
references. No proprietary header or source file is required or bundled.

| Reference | Used for |
|---|---|
| [Kate Land: Using voltage glitching to unleash the A100 in my mining card](https://blog.kate.land/posts/using-voltage-glitching-to-unlock-the-a100/) | Empirical FF field locations, 32-bit replacement-record format and later-record precedence. |
| [Public GA100 option map](https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/ga100-options.json) | Option register addresses, including the corresponding defect masks. |
| [Public GA100 controller map](https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/ga100-core.json) | Controller, CRC, software-override and privilege status addresses. |
| [Public physical-row capture engine](https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/src/lib.rs) | CMD_READ interface, row/data ports, bounded repeated reads, normal debug mode, address checks and restoration. |

Checked on 2026-11-16. References identify the public upstream; they are not fetched
at runtime. The embedded constants define this version's behavior even if upstream
changes. FF locations are research mappings, not an official NVIDIA specification.

The individual Gen3 location remains unresolved. The optional `pcie-gen3-pair`
feature comes from the user-supplied reference toolkit checkout: the Gen3 burn record (PCIe fuse
burns), the PCIe retraining analysis, section 1.2, and
`tools/ff_derive_pcie.py`. They document clearing block-39 data bits 1 and 9
together, not independent identification. No upstream URL for that checkout is
asserted here, and those source files are not bundled. This local experimental
evidence is distinguished from the public primary references above in manifests.
Unclassified reserved-chain records are reported as missing understanding rather
than assumed harmless. Physical aliases of defect fuses, RIR programming,
undocumented GPIO supply paths and ROM flashing remain outside this package's
scope. Explicit main-array programming is provided by the optional public-plan
burner documented below.

The user-supplied **CMP 170HX -> A100-80G: FF Burn Record**, passes 1–6,
supplies the combined reference-die Gen4 completion groups, NVLink mask and
DEVID conversion observations, plus the GSP/PES/ROP, driver, ROM, ECC and NVLink
limitations. These experimental facts are labeled separately from Kate's map;
the block47 individual group permutation is not inferred. NVLINK_DEFECTIVE's
address was checked in the vendored public ga100-options.json (0x0082068c).
Reference row numbers, per-die defect values and reported performance are not
used as targets or guarantees for other cards.


[AUDIT.md](AUDIT.md) describes the additional read-only review of all 16 supplied
reference tool scripts and their reference fixture. The optional validator reads
that separately supplied source and compiles selected isolated functions for
synthetic reproductions. No reference toolkit script, card capture, audit output, private
physical map or legacy burner is redistributed in this package.


The original `ffburn.py3` implements the reference toolkit's main-array IDLE/address/WDATA/
CMD_WRITE/poll/readback protocol and public prerequisites described in
`tools/ff_burn.py` and the supplied burn record. It adds exact public-plan
regeneration and baseline checks, shared capture locking, restricted MMIO ports,
DEBUGCTRL=0, checks after durable intent and after staging data, failure-stop
logging and repeated full-array verification. It performs no supply/GPIO/reset,
override setup, SENSE, RIR, ROM flashing or training. No hardware validation is
claimed; [BURNER.md](BURNER.md) documents its interfaces and limits.


Credit to **xPatrik (Discord)** for research contributions and supplied reference
material. Source labels describe provenance; they do not establish validation
of empirical mappings on other cards.
