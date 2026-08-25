"""Synthesise attacked boots from a clean one.

No public corpus of TPM/IMA measurement logs exists, so the evaluation set is
generated: N clean boots for the baseline, then these four mutations for the
attack class. Every mutation is disclosed in the submission's Datasets field.

The interesting one is `substitute`. It relocates a binary that is genuinely
present and genuinely signed elsewhere on the system to a boot position it
never occupies. Its hash is valid. An allowlist checker sees nothing. Only the
sequence is wrong -- which is exactly how BlackLotus passed Secure Boot, by
shipping validly signed but vulnerable binaries.
"""
import random
from dataclasses import replace


def tamper(events, rng):
    """Flip a byte in one measured file. Allowlist checkers catch this."""
    i = rng.randrange(len(events))
    bad = "%064x" % rng.getrandbits(256)
    return events[:i] + [replace(events[i], file_hash=bad)] + events[i + 1:], i


def insert(events, rng):
    """Load a module that has never been on this machine."""
    i = rng.randrange(len(events))
    rogue = replace(events[i],
                    path="/lib/modules/rogue/implant.ko",
                    file_hash="%064x" % rng.getrandbits(256))
    return events[:i] + [rogue] + events[i:], i


def reorder(events, rng):
    """Same components, permuting execution order across steps."""
    if len(events) < 4:
        i, j = 0, len(events) - 1
    else:
        i = rng.randrange(1, len(events) - 3)
        j = i + rng.randrange(2, min(5, len(events) - i))
    out = list(events)
    out[i], out[j] = out[j], out[i]
    return out, i


def substitute(events, rng):
    """Relocate a real, validly signed binary to a position it never occupies.

    Hash valid. Path known. Signature intact. Sequence novel.
    """
    i = rng.randrange(len(events) // 2, len(events))
    donor = events[rng.randrange(0, len(events) // 4)]
    return events[:i] + [donor] + events[i:], i


ATTACKS = {
    "tamper": tamper,
    "insert": insert,
    "reorder": reorder,
    "substitute": substitute,
}


def apply(events, attack, seed=0):
    if attack not in ATTACKS:
        raise KeyError(f"unknown attack {attack!r}; pick from {sorted(ATTACKS)}")
    return ATTACKS[attack](list(events), random.Random(seed))
