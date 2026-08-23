"""Turn a measurement event into a sequence token.

This is the part nothing off the shelf does. Sequence models (DeepLog, LogBERT)
expect a vocabulary of discrete tokens; IMA hands you structured hash records.
How you project a record onto a token decides what the model is able to see.

Two projections per event:

    identity -- what was loaded, stable across boots of an unmodified system
    content  -- the file hash, which changes the moment a byte changes

An allowlist checker only ever compares content. Comparing the *order* of
identity is what catches a validly signed component loaded at the wrong point
in the boot -- the BlackLotus shape, where every signature checks out.
"""
import re

# Paths carry versions, build ids and pids that differ between boots but mean
# the same thing. Collapse them so the vocabulary stays stable.
_NOISE = [
    (re.compile(r"/proc/\d+/"), "/proc/<pid>/"),
    (re.compile(r"\d+\.\d+\.\d+[-\w.]*"), "<ver>"),
    (re.compile(r"[0-9a-f]{16,}"), "<hex>"),
    (re.compile(r"/tmp/[^/]+"), "/tmp/<tmp>"),
]


def normalize(path):
    for pattern, replacement in _NOISE:
        path = pattern.sub(replacement, path)
    return path


def identity(event):
    return normalize(event.path)


def content(event):
    return event.file_hash


def sequence(events):
    return [identity(e) for e in events]
