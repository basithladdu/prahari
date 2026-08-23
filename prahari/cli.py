"""prahari -- behavioural boot attestation for Linux."""
import argparse
import sys
from pathlib import Path

from . import detect, explain, inject, parse, pqc, viz

BASELINE = Path("baseline.json")


def _load(paths):
    return [parse.read(p) for p in paths]


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
    if args.viz:
        print("timeline -> " + viz.timeline(events, findings, args.viz))
    if not findings:
        print("OK: boot matches baseline")
        return
    for f in findings:
        print(f"[{f.severity:6}] {f.kind:9} {f.path}\n           {f.detail}")
    print()
    print(explain.explain(findings, baseline.boots))


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
    p.set_defaults(func=cmd_check)

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
