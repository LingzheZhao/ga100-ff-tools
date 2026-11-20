# Sources

The scripts are original Python and shell code. Register names, addresses, the
FF record format and field locations come from these public references and the
supplied research below. No proprietary header, driver source or ROM is bundled
or needed.

| Reference | Used for |
|---|---|
| [Kate Land: Using voltage glitching to unleash the A100 in my mining card](https://blog.kate.land/posts/using-voltage-glitching-to-unlock-the-a100/) | FF record format (`data << 16 \| block << 6 \| chain`), later-record precedence, field locations, and the Goldilocks glitch with SENSE_CTRL arming. |
| [Public GA100 option map](https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/ga100-options.json) | Option and defect-mask register addresses, including `NVLINK_DEFECTIVE` (0x82068C). |
| [Public GA100 controller map](https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/data/ga100-core.json) | Fuse controller, CRC, software-override and privilege registers. |
| [Public physical-row capture engine](https://github.com/kate-land/ga100vfi/blob/main/gpu0-registers/crates/gpu0-capture/src/lib.rs) | CMD_READ row/data interface. |

Checked 2026-11-16 to 2026-11-19. They are not fetched at runtime. FF locations
are research mappings, not an NVIDIA specification.

Supplied research (credit **xPatrik**, Discord), not public:

- The **CMP 170HX -> A100-80G FF burn record**: the PCIe records (chain 2 blocks
  39/46/47/49 to clear the Gen3 gates and bring `PCIE_MAGIC_BITS_D` to
  0x00200000), the NVLink record, and the GSP boot failure when SM records are
  burned without the matching PES/ROP_L2 records. The block-39 Gen3 bits are
  cleared as a pair; which bit controls the speed alone is unresolved.
- The `ff_burn.py` write protocol (IDLE, address, WDATA, CMD_WRITE, poll,
  read back) and its prerequisites.

The PCIe values were then confirmed on three further dies with these scripts.
Per-die rows and defect masks from any source are never reused as targets for
another card: every card is planned from its own dump.

Benchmarks (`bench/`):

- `bench.cu` is `benchmark/nvidia_bench.cu` from
  [asm64-hooligan/cmpunlocker](https://github.com/asm64-hooligan/cmpunlocker),
  GPL-2.0-only; the licence text is in `bench/licenses/GPL-2.0.txt`. Only its
  header comment was changed (file name).
- `sm_stress.py` is original.
- [GpuZelenograd/memtest_vulkan](https://github.com/GpuZelenograd/memtest_vulkan)
  is linked, not bundled.

[dalzyu/pico-ga100vfi](https://github.com/dalzyu/pico-ga100vfi) is linked as a
separate glitching toolchain; nothing from it is bundled or invoked.
