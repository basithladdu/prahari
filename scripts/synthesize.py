"""Generate synthetic boot logs so the demo runs without a VM.

Real evaluation uses captured boots (scripts/capture.sh). This exists so a
reviewer can reproduce the headline comparison in one command.
"""
import hashlib
import random
import sys
from pathlib import Path

# Authentic multi-stage boot sequence matching real Linux IMA + TPM measurement logs
BOOT_STAGES = [
    # 1. Firmware & TPM Measurement Stage
    [
        "boot_aggregate",
        "/boot/efi/EFI/BOOT/BOOTX64.EFI",
        "/boot/efi/EFI/ubuntu/shimx64.efi",
        "/boot/efi/EFI/ubuntu/grubx64.efi",
        "/boot/grub/grub.cfg",
    ],
    # 2. Kernel Core & Early Boot Stage
    [
        "/boot/vmlinuz-6.8.0-40-generic",
        "/boot/initrd.img-6.8.0-40-generic",
        "/init",
        "/etc/fstab",
        "/etc/ld.so.cache",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ],
    # 3. Init System & Systemd Units
    [
        "/bin/systemd",
        "/etc/systemd/system.conf",
        "/lib/systemd/systemd-sysctl",
        "/lib/systemd/systemd-journald",
        "/lib/systemd/systemd-udevd",
    ],
    # 4. Kernel Modules & Drivers
    [
        "/lib/modules/6.8.0-40-generic/kernel/drivers/virtio_net.ko",
        "/lib/modules/6.8.0-40-generic/kernel/drivers/virtio_blk.ko",
        "/lib/modules/6.8.0-40-generic/kernel/fs/ext4/ext4.ko",
        "/lib/modules/6.8.0-40-generic/kernel/net/ipv4/tcp_bbr.ko",
    ],
    # 5. Core System Services & Daemons
    [
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/sbin/sshd",
        "/usr/bin/dbus-daemon",
        "/usr/sbin/cron",
        "/usr/bin/login",
    ]
]


def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()


def main(count=5, outdir="boots"):
    Path(outdir).mkdir(exist_ok=True)
    for b in range(count):
        rng = random.Random(b % 2)  # Consistent alternating benign states (e.g. standard boot vs boot with maintenance daemon)
        seq = []
        for stage in BOOT_STAGES:
            stage_seq = list(stage)
            if (b % 2 == 1) and len(stage_seq) > 3:
                stage_seq[-2], stage_seq[-1] = stage_seq[-1], stage_seq[-2]
            seq.extend(stage_seq)
            
        path = Path(outdir) / f"boot-{b}.log"
        lines = []
        for i, p in enumerate(seq):
            pcr = 10 if i > 0 else 0
            lines.append(f"{pcr} {digest(p)[:40]} ima-ng sha256:{digest(p)} {p}\n")
        path.write_text("".join(lines), encoding="utf-8")
        
    print(f"wrote {count} realistic multi-stage synthetic boots to {outdir}/")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
