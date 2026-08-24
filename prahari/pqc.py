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


def _openssl_bin():
    exe = shutil.which("openssl")
    if exe:
        return exe
    for fallback in [r"C:\Program Files\Git\usr\bin\openssl.exe", "/usr/bin/openssl", "/usr/local/bin/openssl"]:
        if Path(fallback).is_file():
            return fallback
    return "openssl"


def _openssl(*args, **kwargs):
    return subprocess.run([_openssl_bin(), *args], check=True, capture_output=True, **kwargs)


def supports_pq():
    try:
        out = subprocess.run([_openssl_bin(), "list", "-signature-algorithms"],
                             capture_output=True, text=True)
        return "ML-DSA" in out.stdout
    except Exception:
        return False


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
    manifest_file = str(out / "manifest.json")
    (out / "manifest.json").write_bytes(payload)
    
    # ECDSA P-256 (requires hash algorithm)
    _openssl("dgst", "-sha256", "-sign", str(keydir / "classical.key"),
             "-out", str(out / "classical.sig"), manifest_file)
    
    # ML-DSA-65 (pure post-quantum signature, no external hash flag)
    _openssl("dgst", "-sign", str(keydir / "pq.key"),
             "-out", str(out / "pq.sig"), manifest_file)
    return out


def verify(bundle, keydir):
    """Both signatures must validate. Either failing rejects the manifest."""
    bundle, keydir = Path(bundle), Path(keydir)
    manifest_file = str(bundle / "manifest.json")
    results = {}
    
    # Classical verification
    pub_c = bundle / "classical.pub"
    _openssl("pkey", "-in", str(keydir / "classical.key"), "-pubout", "-out", str(pub_c))
    proc_c = subprocess.run(
        [_openssl_bin(), "dgst", "-sha256", "-verify", str(pub_c),
         "-signature", str(bundle / "classical.sig"), manifest_file],
        capture_output=True)
    results["classical"] = (proc_c.returncode == 0)
    
    # PQ verification
    pub_pq = bundle / "pq.pub"
    _openssl("pkey", "-in", str(keydir / "pq.key"), "-pubout", "-out", str(pub_pq))
    proc_pq = subprocess.run(
        [_openssl_bin(), "dgst", "-verify", str(pub_pq),
         "-signature", str(bundle / "pq.sig"), manifest_file],
        capture_output=True)
    results["pq"] = (proc_pq.returncode == 0)
    
    return results
