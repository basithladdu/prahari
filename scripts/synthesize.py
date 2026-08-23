"""Generate synthetic boot logs so the demo runs without a VM.

Real evaluation uses captured boots (scripts/capture.sh). This exists so a
reviewer can reproduce the headline comparison in one command.
"""
import hashlib
import random
import sys
from pathlib import Path

CORE = (["boot_aggregate"]
        + [f"/usr/lib/x86_64-linux-gnu/lib{n}.so.6"
           for n in ("c", "m", "pthread", "dl", "z", "ssl", "crypto")]
        + [f"/usr/bin/{b}"
           for b in ("systemd", "bash", "sshd", "cron", "dbus-daemon", "login")]
        + [f"/lib/modules/6.8.0-40/kernel/drivers/{d}.ko"
           for d in ("virtio_net", "virtio_blk", "ext4")])


def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()


def main(count=5, outdir="boots"):
    Path(outdir).mkdir(exist_ok=True)
    for b in range(count):
        rng = random.Random(b)
        seq = list(CORE)
        if b:  # benign jitter: a package tool runs on some boots
            seq.insert(rng.randrange(2, len(seq)), "/usr/bin/apt-get")
        path = Path(outdir) / f"boot-{b}.log"
        path.write_text("".join(
            f"10 {digest(p)[:40]} ima-ng sha256:{digest(p)} {p}\n" for p in seq))
    print(f"wrote {count} synthetic boots to {outdir}/")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 5)
