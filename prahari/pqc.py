"""Hybrid post-quantum manifest signing.

The boot manifest -- every measured path and its hash -- is signed twice:
ECDSA P-256 for today, ML-DSA-65 (FIPS 204) for after a cryptanalytically
relevant quantum computer exists. RFC 9019 calls this the hybrid pattern; a
verifier must accept both or reject the manifest.

OpenSSL 3.5 ships ML-DSA natively, so there is no exotic dependency here.
"""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from . import tokens

PQ_ALG = "ML-DSA-65"
CLASSICAL_ALG = "EC"


def manifest(events):
    """Canonical, order-preserving record of what this boot measured."""
    body = [{"path": tokens.identity(e), "hash": e.file_hash} for e in events]
    return json.dumps(body, separators=(",", ":"), sort_keys=False).encode()


def digest(events):
    return hashlib.sha256(manifest(events)).hexdigest()


def _openssl(*args, **kwargs):
    return subprocess.run(["openssl", *args], check=True, capture_output=True, **kwargs)


def supports_pq():
    if not shutil.which("openssl"):
        return False
    out = subprocess.run(["openssl", "list", "-signature-algorithms"],
                         capture_output=True, text=True)
    return "ML-DSA" in out.stdout


def keygen(outdir):
    """Generate both halves of the hybrid key pair."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    _openssl("ecparam", "-name", "prime256v1", "-genkey",
             "-out", str(outdir / "classical.key"))
    if supports_pq():
        _openssl("genpkey", "-algorithm", PQ_ALG, "-out", str(outdir / "pq.key"))
    else:
        raise RuntimeError(
            "This OpenSSL has no ML-DSA. Install OpenSSL 3.5+, or use liboqs-python.")
    return outdir


def sign(events, keydir, out):
    """Write manifest + both signatures."""
    keydir, out = Path(keydir), Path(out)
    payload = manifest(events)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_bytes(payload)
    for name, key in (("classical", "classical.key"), ("pq", "pq.key")):
        _openssl("dgst", "-sha256", "-sign", str(keydir / key),
                 "-out", str(out / f"{name}.sig"), str(out / "manifest.json"))
    return out


def verify(bundle, keydir):
    """Both signatures must validate. Either failing rejects the manifest."""
    bundle, keydir = Path(bundle), Path(keydir)
    results = {}
    for name, key in (("classical", "classical.key"), ("pq", "pq.key")):
        pub = bundle / f"{name}.pub"
        _openssl("pkey", "-in", str(keydir / key), "-pubout", "-out", str(pub))
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(pub),
             "-signature", str(bundle / f"{name}.sig"), str(bundle / "manifest.json")],
            capture_output=True)
        results[name] = proc.returncode == 0
    return results
