"""Compare a boot against the learned baseline.

Three findings, in increasing order of what existing tooling can already see:

    tampered -- known path, hash never seen before. Allowlist checkers get this.
    unknown  -- a path that appeared in none of the baseline boots.
    sequence -- known-good components in an order that never occurred.

The third one is the point of the project. Every hash validates, every
signature checks out, and the boot is still wrong.
"""
import json
from collections import defaultdict
from dataclasses import dataclass, asdict

from . import tokens


@dataclass
class Finding:
    kind: str          # tampered | unknown | sequence
    position: int      # index into the boot sequence
    path: str
    detail: str
    severity: str      # high | medium

    def as_dict(self):
        return asdict(self)


def ngrams(seq, n):
    return [tuple(seq[i:i + n]) for i in range(len(seq) - n + 1)]


class Baseline:
    """What a normal boot looks like on this machine.

    Deliberately an n-gram model rather than an LSTM: it converges on a handful
    of boots, where DeepLog needs thousands of sequences. On a machine you can
    only reboot so many times before a deadline, that matters more than F1.
    """

    def __init__(self, n=3):
        self.n = n
        self.hashes = defaultdict(set)
        self.grams = set()
        self.boots = 0

    def learn(self, events):
        seq = tokens.sequence(events)
        for event in events:
            self.hashes[tokens.identity(event)].add(tokens.content(event))
        self.grams.update(ngrams(seq, self.n))
        self.boots += 1
        return self

    def check(self, events):
        seq = tokens.sequence(events)
        findings = []

        for i, event in enumerate(events):
            ident = tokens.identity(event)
            if ident not in self.hashes:
                findings.append(Finding(
                    "unknown", i, event.path,
                    "measured in no baseline boot", "high"))
            elif tokens.content(event) not in self.hashes[ident]:
                findings.append(Finding(
                    "tampered", i, event.path,
                    f"hash {event.file_hash[:16]} not seen for this path", "high"))

        for i, gram in enumerate(ngrams(seq, self.n)):
            if gram not in self.grams:
                findings.append(Finding(
                    "sequence", i, gram[-1],
                    "transition " + " -> ".join(gram) + " never occurred in baseline",
                    "medium"))

        return findings

    def save(self, path):
        with open(path, "w") as fh:
            json.dump({
                "n": self.n,
                "boots": self.boots,
                "hashes": {k: sorted(v) for k, v in self.hashes.items()},
                "grams": [list(g) for g in sorted(self.grams)],
            }, fh, indent=2)

    @classmethod
    def load(cls, path):
        with open(path) as fh:
            blob = json.load(fh)
        baseline = cls(blob["n"])
        baseline.boots = blob["boots"]
        baseline.hashes = defaultdict(set, {k: set(v) for k, v in blob["hashes"].items()})
        baseline.grams = {tuple(g) for g in blob["grams"]}
        return baseline
