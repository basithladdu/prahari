# PRAHARI — portal submission fields

Copy each block into the matching field on the SSM portal.

---

## Title

PRAHARI — Behavioural Boot Attestation with Post-Quantum Signing

---

## Problem Statement

AI-Assisted Secure Boot & Integrity Verification — Develop a secure boot
solution that combines quantum-resistant cryptography with AI-based boot
behavior analysis. The system should verify system integrity and detect abnormal
boot activities, even when traditional signature checks succeed.

---

## Objective

To catch a compromised boot in the one case existing tools are blind to: when
every signature is valid and every hash matches.

Boot attestation today asks a single question — does this file's hash appear on
a list of known-good hashes. PRAHARI adds a second question that nothing
currently asks: is this boot sequence normal for this machine? It also replaces
the classical-only signing chain with a hybrid one that survives the arrival of
a quantum computer.

---

## Description

The Linux kernel already records every file it measures during and after boot,
in the order it measured them, as plain text at
`/sys/kernel/security/ima/ascii_runtime_measurements`. Where a TPM is present,
firmware measurements are similarly available at
`/sys/kernel/security/tpm0/ascii_bios_measurements`. PRAHARI reads these.

**Tokenising.** Each measurement is projected onto two separate axes. Identity
is the normalised path — what was loaded — which stays stable across boots of an
unmodified system. Content is the file hash, which changes the instant a byte
changes. Existing tools only ever compare content. This projection is the
original contribution: sequence models expect a vocabulary of discrete tokens,
and how a measurement record maps onto one decides what the model can see at all.

**Learning.** Boot the machine a few times without interference. An n-gram model
over the identity sequence records which transitions occur in a normal boot.

**Checking.** A later boot produces three classes of finding. `tampered` — a
known path carrying a hash never seen before. `unknown` — a path that appeared
in no baseline boot. `sequence` — legitimate, known-good components appearing in
an order that has never occurred. The first two are what an allowlist checker
also catches. The third is the one nothing else sees.

**Signing.** The manifest of what a boot measured is signed twice: ECDSA P-256
and ML-DSA-65 (FIPS 204). A verifier must accept both, following the hybrid
pattern of RFC 9019. OpenSSL 3.5 provides ML-DSA natively.

**Explaining.** A language model writes the findings up in plain English. It
receives findings the detector has already made and cannot create, suppress or
reweight one, so a hallucination cannot manufacture or hide a detection.

**Evaluating.** Four attack mutations are generated against a captured clean
boot: `tamper` (alter a hash), `insert` (add an unknown module), `reorder` (swap
two events), and `substitute` — relocating a genuine, validly signed file to a
position in the boot it never occupies. On `substitute` every hash remains
valid; only the ordering betrays it. Allowlist checking detects two of the four.
PRAHARI detects all four.

---

## Novelty

Two things are new here.

**Applying sequence anomaly detection to boot measurement logs.** Machine
learning on log sequences is a mature field — DeepLog, LogBERT, loglizer and a
large body of published work. Separately, TPM and IMA measured boot is a mature
field, with Keylime as the CNCF reference implementation. The two have not been
joined. Every attestation system in production compares hashes against a
manually maintained allowlist; none models the ordering. We searched for prior
work combining machine-learned anomaly detection with TPM/PCR or IMA measurement
logs and found none.

**The threat this addresses is real and current.** BlackLotus bypassed UEFI
Secure Boot in 2023 not by breaking cryptography but by shipping genuine,
validly signed Microsoft binaries containing an exploitable flaw. Signature
verification passed. Bootkitty demonstrated the same approach against Ubuntu via
LogoFAIL. An allowlist checker is structurally incapable of seeing either,
because nothing it inspects is wrong. Ordering is the signal that remains.

A supporting choice is also deliberate. We use an n-gram model rather than
DeepLog or LogBERT because those require thousands of sequences to train, and a
physical machine can realistically be rebooted perhaps a dozen times. The n-gram
model converges within four or five boots, and every alert resolves to a
specific transition that can be printed and argued with, rather than a score
emitted by weights.

---

## Innovation

The practical innovation is that this needs no new hardware, no kernel patch and
no custom firmware. The kernel already writes the data; it has simply never been
read this way. Turning on measurement is a single kernel command-line flag, and
IMA populates its log even on a machine with no TPM, so the technique deploys on
existing fleets immediately.

The security innovation is a second, independent detection layer beneath
cryptographic verification. Signatures answer provenance. Sequence answers
behaviour. An attacker who obtains a valid signing key, or who abuses a signed
but vulnerable binary as BlackLotus did, defeats the first and must still
reproduce the exact ordering of a normal boot to defeat the second.

The post-quantum layer addresses the most time-critical part of the migration.
NSA CNSA 2.0 identifies firmware signing as the highest-priority signature use
case for the quantum transition, because firmware is the hardest thing to change
once a device has shipped. A device manufactured today with a classical-only
boot chain cannot easily be fixed later.

---

## Data Set Used

No public corpus of IMA or TPM measurement logs exists — itself evidence of how
little the area has been studied. The evaluation set is generated on the machine
under test.

Baseline: N clean boots of the machine, captured from securityfs.

Attack class: four documented mutations of a clean boot — `tamper`, `insert`,
`reorder`, `substitute` — implemented in `prahari/inject.py` and disclosed in
full. A generator (`scripts/synthesize.py`) also produces synthetic logs so a
reviewer can reproduce the comparison without provisioning a virtual machine.

Measurement logs contain file paths and cryptographic hashes only. No personal
data is collected, and nothing is transmitted off the machine except when the
optional explanation feature is used, which sends only the list of findings.
This is consistent with the Digital Personal Data Protection Act, 2023.

---

## Tech Stack

Language: Python 3.9+

Cryptography: OpenSSL 3.5 (Apache-2.0) for ML-DSA-65 (FIPS 204) and ECDSA
P-256. liboqs-python is supported as an alternative provider.

Platform interfaces: Linux IMA and the TPM event log, read through securityfs.
tpm2-tools / tpm2-pytss (BSD-3 / MIT) for binary event log parsing where a TPM
is present. Development and testing against swtpm under QEMU with OVMF.

Interface: Textual (MIT) for the terminal UI; plotly (MIT) for the boot sequence
chart.

Explanation: Anthropic Claude API, used only to narrate findings.

Note: WSL2 cannot be used for development, as it provides no TPM support
(microsoft/WSL issue #10777). A conventional Linux virtual machine is required.

AI-assisted development: Claude was used as a coding assistant. All design
decisions — the token projection, the choice of an n-gram model over an LSTM,
the attack taxonomy — are the team's own, and the team can defend every one.

---

## Model Type

Inbuilt Model.

The detection model is ours: an n-gram sequence model over a token projection we
defined, chosen over a trained neural model for two reasons. It converges on the
handful of boots a real machine can supply, and every finding traces to a named
transition rather than to weights. That inspectability matters more than F1 for
a security tool whose alerts a human must act on.

A large language model (Claude, via the Anthropic API) is used solely to
translate findings into readable prose. It takes no part in detection, and the
system runs fully without it.

---

## GitHub Link

https://github.com/basithladdu/prahari
