#!/bin/bash
# gpu-stack: turn the NVIDIA driver and gpu-unlock on or off for the next boot.
#
#   sudo gpu-stack disable   block nvidia* + gpu_unlock from the next boot on
#   sudo gpu-stack enable    undo that
#   sudo gpu-stack status    what the next boot and this boot use
#   BDF=0000:01:00.0 gpu-stack status   also show that card's link and driver
#
# disable adds a kernel-level module_blacklist through a GRUB drop-in. The
# kernel then refuses those modules whoever asks (modprobe, insmod, udev,
# nvidia-modprobe), which a modprobe.d blacklist alone did not achieve. It also
# masks the units that load or poke the card. enable removes the drop-in and
# unmasks them. Neither touches the card itself; both need a reboot (cold boot
# recommended so the card starts from power-on state).
set -euo pipefail

DROPIN=/etc/default/grub.d/99-gpu-stack-disable.cfg
# The last module_blacklist= on the command line wins, so keep nouveau in it.
MODULES=nouveau,nvidia,nvidia_drm,nvidia_modeset,nvidia_uvm,nvidia_peermem,gpu_unlock
UNITS=(gpu-unlock-overrides.service nvidia-cdi-refresh.path nvidia-cdi-refresh.service nvidia-powerd.service)
ENABLED_UNITS=(nvidia-cdi-refresh.path nvidia-powerd.service)
BDF=${BDF:-}

need_root() {
    [[ $EUID -eq 0 ]] || { echo "run as root: sudo $0 $1" >&2; exit 1; }
}

# The module_blacklist the next boot of this kernel will use (last one wins).
next_boot() {
    grep -m1 "linux.*vmlinuz-$(uname -r)" /boot/grub/grub.cfg |
        grep -o 'module_blacklist=[^ ]*' | tail -1 || echo "(none)"
}

status() {
    echo "next boot:  $([[ -f $DROPIN ]] && echo DISABLED || echo enabled)  $(next_boot)"
    echo "this boot:  $(grep -o 'module_blacklist=[^ ]*' /proc/cmdline | tail -1 || echo '(none)')"
    echo "loaded:     $(lsmod | awk '/^(nvidia|gpu_unlock) / {printf "%s ", $1}')"
    for unit in "${UNITS[@]}"; do
        printf '  %-30s %s\n' "$unit" "$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    done
    [[ -n $BDF ]] || return 0
    lspci -k -vv -s "$BDF" 2>/dev/null | grep -E 'LnkSta:|Kernel driver in use' | sed 's/^\s*/  /' || true
}

disable() {
    need_root disable
    mkdir -p "$(dirname "$DROPIN")"
    printf 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT module_blacklist=%s"\n' \
        "$MODULES" > "$DROPIN"
    systemctl mask "${UNITS[@]}"
    update-grub 2>&1 | tail -1
    [[ "$(next_boot)" == "module_blacklist=$MODULES" ]] ||
        { echo "ERROR: grub.cfg does not carry the blacklist: $(next_boot)" >&2; exit 1; }
    echo "DISABLED for the next boot. Power off fully, then cold boot."
}

enable() {
    need_root enable
    rm -f "$DROPIN"
    systemctl unmask "${UNITS[@]}"
    systemctl enable "${ENABLED_UNITS[@]}" 2>/dev/null || true
    update-grub 2>&1 | tail -1
    [[ "$(next_boot)" != *nvidia* ]] ||
        { echo "ERROR: grub.cfg still blacklists nvidia: $(next_boot)" >&2; exit 1; }
    echo "ENABLED for the next boot. Power off fully, then cold boot."
}

case "${1:-status}" in
    disable) disable ;;
    enable) enable ;;
    status) status ;;
    *) echo "usage: $0 enable|disable|status" >&2; exit 2 ;;
esac
