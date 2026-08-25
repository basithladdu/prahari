"""IETF RATS (RFC 9334) Standard JSON Attestation Evidence Generator."""
import datetime
import hashlib
import json
import platform
from dataclasses import asdict
from pathlib import Path

from . import detect, pqc, stages


def generate_evidence(events, baseline: detect.Baseline, findings: list, system_id=None):
    """Generate a verifiable JSON Remote Attestation Evidence Claim."""
    manifest_digest = pqc.digest(events)
    stage_anomalies = stages.check_stage_transitions(events)
    
    # Calculate Risk Score (0.0 = completely clean, 1.0 = critical compromise)
    score = 0.0
    for f in findings:
        if f.kind == "tampered":
            score = max(score, 1.0)
        elif f.kind == "unknown":
            score = max(score, 0.85)
        elif f.kind == "sequence":
            score = max(score, 0.75)
            
    if stage_anomalies and score < 0.6:
        score = max(score, 0.6)
        
    rating = "CLEAN"
    if score >= 0.8:
        rating = "COMPROMISED"
    elif score >= 0.5:
        rating = "SUSPICIOUS"
        
    evidence = {
        "rats_header": {
            "type": "IETF_RATS_EVIDENCE_RFC9334",
            "generator": "PRAHARI-v1.0-MeitY-Edition",
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_system": {
                "system_id": system_id or platform.node(),
                "os": platform.system(),
                "release": platform.release(),
                "arch": platform.machine(),
            }
        },
        "boot_measurement_claims": {
            "total_events_measured": len(events),
            "manifest_sha256": manifest_digest,
            "boot_aggregate": events[0].file_hash if events else None,
            "stages_observed": list(dict.fromkeys(stages.classify_path(e.path).value for e in events)),
        },
        "behavioral_attestation": {
            "baseline_boots_learned": baseline.boots,
            "baseline_transitions_modeled": len(baseline.grams),
            "findings_count": len(findings),
            "findings": [f.as_dict() for f in findings],
            "stage_violations": [asdict(a) for a in stage_anomalies],
            "overall_anomaly_score": round(score, 2),
            "trust_rating": rating,
        },
        "post_quantum_claims": {
            "classical_alg": "ECDSA_P256",
            "post_quantum_alg": pqc.PQ_ALG,
            "hybrid_mode": "RFC_9019_CONCATENATED",
        }
    }
    return evidence
