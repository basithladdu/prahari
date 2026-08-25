"""prahari -- behavioural boot attestation for Linux."""
import argparse
import sys
from pathlib import Path

from . import attest, benchmark, detect, explain, inject, parse, pqc, stages, viz

BASELINE = Path("baseline.json")


def _load(paths):
    expanded = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.log")))
        else:
            expanded.append(path)
    return [parse.read(p) for p in expanded]


def cmd_learn(args):
    baseline = detect.Baseline(args.n)
    for boot in _load(args.logs):
        baseline.learn(boot)
    baseline.save(args.out)
    print(f"learned {baseline.boots} boots, "
          f"{len(baseline.hashes)} paths, {len(baseline.grams)} transitions -> {args.out}")


def cmd_check(args):
    baseline = detect.Baseline.load(args.baseline)
    events = parse.read(args.log)
    findings = baseline.check(events)
    
    if args.json:
        import json
        evidence = attest.generate_evidence(events, baseline, findings)
        print(json.dumps(evidence, indent=2))
        return

    if args.viz:
        print("timeline -> " + viz.timeline(events, findings, args.viz))
    if not findings:
        print("OK: boot matches baseline (Risk: 0.0, Trust: CLEAN)")
        return
    for f in findings:
        stage = stages.classify_path(f.path).value
        print(f"[{f.severity.upper():8}] [{stage:<16}] {f.kind:9} {f.path}\n           {f.detail}")
    print()
    print(explain.explain(findings, baseline.boots))


def cmd_attest(args):
    """Generate standardized IETF RATS (RFC 9334) JSON Evidence Claim."""
    import json
    baseline = detect.Baseline.load(args.baseline)
    events = parse.read(args.log)
    findings = baseline.check(events)
    evidence = attest.generate_evidence(events, baseline, findings)
    
    out_path = Path(args.out)
    out_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"IETF RATS Evidence generated -> {out_path} [Rating: {evidence['behavioral_attestation']['trust_rating']}]")


def cmd_benchmark(args):
    """Execute automated empirical ROC evaluation across all attack vectors."""
    boots = _load(args.logs)
    report = benchmark.run_benchmark(boots, seed=args.seed)
    
    print(f"=========================================================================")
    print(f"PRAHARI EMPIRICAL BENCHMARK (Train Boots: {report['baseline_boots']} | Holdout Events: {report['holdout_events']})")
    print(f"=========================================================================\n")
    print(f"{'SCENARIO':<32} {'EXPECTED':<10} {'ALLOWLIST':<12} {'PRAHARI':<12} {'LATENCY'}")
    print("-" * 74)
    
    for r in report["scenarios"]:
        al_str = "DETECT" if r["allowlist_caught"] else "PASS"
        pr_str = "DETECT" if r["prahari_caught"] else "PASS"
        print(f"{r['scenario']:<32} {r['expected']:<10} {al_str:<12} {pr_str:<12} {r['latency_ms']} ms")
        
    print("-" * 74)
    print(f"Allowlist Accuracy: {report['summary']['allowlist_accuracy'] * 100:.1f}%")
    print(f"PRAHARI Accuracy:   {report['summary']['prahari_accuracy'] * 100:.1f}%\n")


def cmd_demo(args):
    """Run every attack past both detectors and print the comparison."""
    boots = _load(args.logs)
    baseline = detect.Baseline(args.n)
    for boot in boots[:-1]:
        baseline.learn(boot)
    clean = boots[-1]

    print(f"baseline: {baseline.boots} boots | holdout: {len(clean)} events\n")
    print(f"{'attack':<12} {'allowlist':<12} {'prahari':<12} caught by")
    print("-" * 58)

    for name in inject.ATTACKS:
        attacked, _ = inject.apply(clean, name, args.seed)
        findings = baseline.check(attacked)
        kinds = {f.kind for f in findings}
        allowlist = bool(kinds & {"tampered", "unknown"})   # what Keylime sees
        ours = bool(kinds)
        print(f"{name:<12} {'DETECT' if allowlist else 'MISS':<12} "
              f"{'DETECT' if ours else 'MISS':<12} {','.join(sorted(kinds)) or '-'}")


def cmd_sign(args):
    events = parse.read(args.log)
    pqc.keygen(args.keys)
    pqc.sign(events, args.keys, args.out)
    print(f"manifest sha256={pqc.digest(events)}")
    print(f"signed with ECDSA P-256 + {pqc.PQ_ALG} -> {args.out}")


def cmd_verify(args):
    results = pqc.verify(args.bundle, args.keys)
    for name, ok in results.items():
        print(f"{name:<10} {'valid' if ok else 'INVALID'}")
    sys.exit(0 if all(results.values()) else 1)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="prahari", description=__doc__)
    ap.add_argument("-n", type=int, default=3, help="n-gram width (default 3)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("learn", help="build a baseline from clean boots")
    p.add_argument("logs", nargs="+")
    p.add_argument("--out", default=BASELINE)
    p.set_defaults(func=cmd_learn)

    p = sub.add_parser("check", help="compare one boot against the baseline")
    p.add_argument("log")
    p.add_argument("--baseline", default=BASELINE)
    p.add_argument("--viz", metavar="OUT.html", help="draw the boot sequence")
    p.add_argument("--json", action="store_true", help="output standardized JSON attestation claim")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("attest", help="generate standardized IETF RATS JSON Evidence Claim")
    p.add_argument("log")
    p.add_argument("--baseline", default=BASELINE)
    p.add_argument("--out", default="evidence.json")
    p.set_defaults(func=cmd_attest)

    p = sub.add_parser("bench", help="run empirical benchmark across attack vectors")
    p.add_argument("logs", nargs="+")
    p.add_argument("--seed", type=int, default=42)
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("demo", help="allowlist vs behavioural, all four attacks")
    p.add_argument("logs", nargs="+")
    p.add_argument("--seed", type=int, default=0)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("ui", help="open the terminal UI")
    p.add_argument("logs", nargs="?", default="boots")
    p.set_defaults(func=lambda a: __import__("prahari.tui", fromlist=["run"]).run(a.logs))

    p = sub.add_parser("sign", help="hybrid-sign a boot manifest")
    p.add_argument("log")
    p.add_argument("--keys", default="keys")
    p.add_argument("--out", default="bundle")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify a signed manifest")
    p.add_argument("bundle")
    p.add_argument("--keys", default="keys")
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
