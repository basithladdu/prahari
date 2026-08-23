"""Read the Linux IMA runtime measurement log.

/sys/kernel/security/ima/ascii_runtime_measurements is an append-only record of
every file the kernel measured, in the order it was measured. One line each:

    <pcr> <template-hash> <template> <alg>:<file-hash> <path>

The first line is always boot_aggregate, a digest over PCRs 0-7. On a machine
with no TPM the aggregate is zeroes and the rest of the log still populates --
which is why this runs in a plain VM with no emulated hardware.
"""
from dataclasses import dataclass
from pathlib import Path

IMA_LOG = Path("/sys/kernel/security/ima/ascii_runtime_measurements")


@dataclass(frozen=True)
class Event:
    pcr: int
    template_hash: str
    template: str
    file_hash: str
    path: str


def parse(text):
    events = []
    for line in text.splitlines():
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            continue
        pcr, template_hash, template, digest, path = parts
        # ima-ng and ima-sig prefix the digest with its algorithm; plain ima does not
        file_hash = digest.split(":", 1)[-1]
        events.append(Event(int(pcr), template_hash, template, file_hash, path.strip()))
    return events


def read(path=IMA_LOG):
    return parse(Path(path).read_text(errors="replace"))
