"""Automated Empirical Evaluation & ROC Benchmark Engine for PRAHARI."""
import time
from . import detect, inject, parse, tokens


def run_benchmark(boots, seed=0):
    """Run an automated benchmark comparing Allowlist vs PRAHARI Behavioral Model."""
    if len(boots) < 2:
        raise ValueError("Need at least 2 boots (baseline + holdout) for benchmark")
        
    train_boots = boots[:-1]
    holdout = boots[-1]
    
    baseline = detect.Baseline(n=3)
    for b in train_boots:
        baseline.learn(b)
        
    results = []
    
    # 1. Clean holdout (True Negative test)
    t0 = time.perf_counter()
    findings = baseline.check(holdout)
    dt = (time.perf_counter() - t0) * 1000.0
    results.append({
        "scenario": "Clean Holdout (Unmodified)",
        "expected": "CLEAN",
        "allowlist_caught": False,
        "prahari_caught": len(findings) > 0,
        "caught_by": [f.kind for f in findings],
        "latency_ms": round(dt, 2),
    })
    
    # 2. Attack mutations (True Positive tests)
    for attack in inject.ATTACKS:
        attacked, _ = inject.apply(holdout, attack, seed=seed)
        t0 = time.perf_counter()
        findings = baseline.check(attacked)
        dt = (time.perf_counter() - t0) * 1000.0
        
        kinds = {f.kind for f in findings}
        allowlist = bool(kinds & {"tampered", "unknown"})
        prahari = bool(kinds)
        
        results.append({
            "scenario": f"Attack: {attack.upper()}",
            "expected": "ATTACK",
            "allowlist_caught": allowlist,
            "prahari_caught": prahari,
            "caught_by": sorted(kinds),
            "latency_ms": round(dt, 2),
        })
        
    return {
        "baseline_boots": len(train_boots),
        "holdout_events": len(holdout),
        "scenarios": results,
        "summary": {
            "allowlist_accuracy": sum(1 for r in results if r["allowlist_caught"] == (r["expected"] == "ATTACK")) / len(results),
            "prahari_accuracy": sum(1 for r in results if r["prahari_caught"] == (r["expected"] == "ATTACK")) / len(results),
        }
    }
