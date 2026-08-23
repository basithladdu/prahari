#!/usr/bin/env bash
# Turn on IMA measurement, then reboot. Run once per VM.
set -euo pipefail

if [ ! -d /sys/kernel/security ]; then
    sudo mount -t securityfs security /sys/kernel/security
fi

if [ ! -d /sys/kernel/security/integrity/ima ]; then
    echo "This kernel has no IMA (CONFIG_IMA is off). Use an Ubuntu Server image."
    exit 1
fi

sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 ima_policy=tcb"/' \
    /etc/default/grub
sudo update-grub
echo "IMA enabled. Reboot, then run scripts/capture.sh"
