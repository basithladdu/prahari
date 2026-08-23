# PRAHARI

**Behavioural boot attestation for Linux.** Detects a compromised boot even when
every signature checks out.

Built for C-DAC / MeitY *AI Enabled Operating System Hackathon 2026* —
Track: AI Usage at OS & Kernel Level — Problem Statement:
*AI-Assisted Secure Boot & Integrity Verification*.

---

## The gap

Existing attestation is **allowlist-based**. Keylime, the CNCF/IBM reference
implementation, compares each measured file against a hand-maintained list of
known-good hashes. It answers one question: *does this hash match?*

It cannot answer the other one: *is this boot sequence normal?*

That matters because the interesting attacks don't break hashes. BlackLotus
bypassed UEFI Secure Boot by shipping its own **validly signed but vulnerable**
binaries — signature verification passed and the machine was compromised anyway.
Bootkitty did the same to Ubuntu via LogoFAIL. In both cases an allowlist checker
sees nothing wrong, because nothing it looks at *is* wrong.

PRAHARI learns what a normal boot looks like on this machine and flags boots that
deviate — including boots where every component is individually legitimate.

## How it works

```
IMA / TPM measurement log  ->  tokenizer  ->  baseline  ->  findings  ->  explanation
                                                              |
                                              hybrid ML-DSA + ECDSA manifest
```

1. **Collect.** The kernel already records every file it measured, in order, at
   `/sys/kernel/security/ima/ascii_runtime_measurements`. Plain text, append-only.
2. **Tokenize.** Project each measurement onto two axes — *identity* (what was
   loaded) and *content* (its hash). Allowlist checkers only ever compare content.
3. **Learn.** A few clean boots give an n-gram model over identity sequences.
4. **Check.** Three finding classes, in increasing order of what existing tools see:

   | finding | meaning | allowlist checkers |
   |---|---|---|
   | `tampered` | known path, unseen hash | catch it |
   | `unknown` | path in no baseline boot | catch it |
   | `sequence` | legitimate components, impossible order | **miss it** |

5. **Sign.** The boot manifest is signed twice — ECDSA P-256 and ML-DSA-65
   (FIPS 204), the RFC 9019 hybrid pattern. NSA CNSA 2.0 names firmware signing
   the highest-priority use case for the post-quantum transition.
6. **Explain.** The model narrates findings the detector already made. It never
   decides whether a boot is compromised, so a hallucination can neither
   manufacture nor suppress a detection.

## Quick start

```bash
sudo bash scripts/setup_ima.sh    # once; reboots into ima_policy=tcb
sudo bash scripts/capture.sh      # after each reboot, 4-5 times
python -m prahari.cli learn boots/*.log
python -m prahari.cli check boots/boot-latest.log
```

See the headline result:

```bash
python -m prahari.cli demo boots/*.log
```

## Why n-grams and not an LSTM

DeepLog and LogBERT need thousands of sequences. You can reboot a machine maybe
a dozen times before a deadline. An n-gram model over the identity sequence
converges on a handful of boots and stays inspectable — every finding traces to
a specific transition you can print. The LSTM path is wired but is the
large-fleet story, not the single-machine one.

## Requirements

- Linux with `CONFIG_IMA` (Ubuntu Server ships it). **Not WSL2** — no TPM support.
- OpenSSL 3.5+ for ML-DSA (`openssl list -signature-algorithms | grep ML-DSA`).
- Python 3.9+. `ANTHROPIC_API_KEY` for narrative explanations (optional).

A TPM is *not* required: IMA populates its log without one, so the whole system
runs in a plain VM. With a TPM (or `swtpm` under QEMU/OVMF) the measured-boot
log at `/sys/kernel/security/tpm0/ascii_bios_measurements` extends coverage back
through firmware.

## Third-party components

| Component | Licence | Use |
|---|---|---|
| OpenSSL 3.5 | Apache-2.0 | ML-DSA-65 and ECDSA signing |
| anthropic | MIT | explanation layer |
| tpm2-tools / tpm2-pytss | BSD-3 / MIT | TPM event log (optional tier) |

The measurement parser, tokenizer, baseline model, detector and attack
generator are original to this project.

## Datasets

No public corpus of IMA or TPM measurement logs exists. The evaluation set is
generated on the machine under test: N clean boots for the baseline, then four
disclosed mutations for the attack class — `tamper`, `insert`, `reorder`,
`substitute`. No personal data is collected; measurement logs contain file paths
and hashes only.

## Licence

MIT — see [LICENSE](LICENSE).
