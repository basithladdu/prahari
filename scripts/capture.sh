#!/usr/bin/env bash
# Snapshot this boot's measurement log. Run after each reboot to grow the baseline.
set -euo pipefail
mkdir -p boots
timestamp="$(date +%Y%m%d-%H%M%S)"
out="boots/boot-${timestamp}.log"

# 1. Capture Linux kernel IMA runtime measurement log
if [ -f /sys/kernel/security/ima/ascii_runtime_measurements ]; then
    sudo cat /sys/kernel/security/ima/ascii_runtime_measurements > "$out"
elif [ -f /sys/kernel/security/integrity/ima/ascii_runtime_measurements ]; then
    sudo cat /sys/kernel/security/integrity/ima/ascii_runtime_measurements > "$out"
else
    echo "Error: Linux IMA securityfs measurements not found. Run scripts/setup_ima.sh and reboot." >&2
    exit 1
fi

# 2. Capture hardware / vTPM event log if available
if [ -f /sys/kernel/security/tpm0/ascii_bios_measurements ]; then
    sudo cat /sys/kernel/security/tpm0/ascii_bios_measurements > "boots/tpm-${timestamp}.log"
fi

echo "Captured $(wc -l < "$out") boot measurements -> $out"
