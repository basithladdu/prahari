#!/usr/bin/env bash
# Snapshot this boot's measurement log. Run after each reboot to grow the baseline.
set -euo pipefail
mkdir -p boots
out="boots/boot-$(date +%Y%m%d-%H%M%S).log"
sudo cat /sys/kernel/security/ima/ascii_runtime_measurements > "$out"
echo "$(wc -l < "$out") events -> $out"
