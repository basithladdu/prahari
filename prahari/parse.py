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


class MeasurementParseError(ValueError):
    """The measurement log is empty or contains an invalid record."""


def parse(text):
    events = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            raise MeasurementParseError(
                f"invalid IMA measurement at line {line_number}: expected 5 fields")
        pcr, template_hash, template, digest, path = parts
        try:
            pcr = int(pcr)
        except ValueError as exc:
            raise MeasurementParseError(
                f"invalid IMA measurement at line {line_number}: PCR must be an integer") from exc

        # ima-ng and ima-sig prefix the digest with its algorithm; plain ima does not
        file_hash = digest.split(":", 1)[-1]
        path = path.strip()
        if not file_hash or not path:
            raise MeasurementParseError(
                f"invalid IMA measurement at line {line_number}: hash and path are required")
        events.append(Event(pcr, template_hash, template, file_hash, path))

    if not events:
        raise MeasurementParseError("measurement log contains no IMA events")
    return events


def read(path=IMA_LOG):
    return parse(Path(path).read_text(errors="replace"))
