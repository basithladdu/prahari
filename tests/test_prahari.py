import tempfile
import unittest
from pathlib import Path

from prahari import attest, benchmark, detect, inject, parse, pqc, stages, tokens


class TestPrahari(unittest.TestCase):
    def setUp(self):
        self.boot_a = [
            parse.Event(10, 'h0', 'ima-ng', 'sha256:1111', 'boot_aggregate'),
            parse.Event(10, 'h1', 'ima-ng', 'sha256:2222', '/init'),
            parse.Event(10, 'h2', 'ima-ng', 'sha256:3333', '/bin/systemd'),
            parse.Event(10, 'h3', 'ima-ng', 'sha256:4444', '/etc/systemd/system.conf'),
            parse.Event(10, 'h4', 'ima-ng', 'sha256:5555', '/lib/modules/kernel.ko'),
        ]
        self.boot_b = [
            parse.Event(10, 'h0', 'ima-ng', 'sha256:1111', 'boot_aggregate'),
            parse.Event(10, 'h1', 'ima-ng', 'sha256:2222', '/init'),
            parse.Event(10, 'h2', 'ima-ng', 'sha256:3333', '/bin/systemd'),
            parse.Event(10, 'h3', 'ima-ng', 'sha256:4444', '/etc/systemd/system.conf'),
            parse.Event(10, 'h4', 'ima-ng', 'sha256:5555', '/lib/modules/kernel.ko'),
        ]

    def test_token_projection(self):
        ident = tokens.identity(self.boot_a[1])
        content = tokens.content(self.boot_a[1])
        self.assertEqual(ident, '/init')
        self.assertEqual(content, 'sha256:2222')

    def test_measurement_parsing_fails_closed(self):
        valid = '10 template-hash ima-ng sha256:abcd /usr/bin/example'
        self.assertEqual(parse.parse(valid + '\n\n')[0].path, '/usr/bin/example')
        with self.assertRaisesRegex(parse.MeasurementParseError, 'line 2'):
            parse.parse(valid + '\ntruncated measurement')
        with self.assertRaisesRegex(parse.MeasurementParseError, 'no IMA events'):
            parse.parse('\n')

        with self.assertRaisesRegex(ValueError, 'empty measurement stream'):
            detect.Baseline(n=3).learn([])
        base = detect.Baseline(n=3).learn(self.boot_a)
        with self.assertRaisesRegex(ValueError, 'empty measurement stream'):
            base.check([])

    def test_baseline_learning_and_clean_check(self):
        base = detect.Baseline(n=3)
        base.learn(self.boot_a)
        base.learn(self.boot_b)
        self.assertEqual(base.boots, 2)
        findings = base.check(self.boot_a)
        self.assertEqual(len(findings), 0)

    def test_tamper_attack_detected(self):
        base = detect.Baseline(n=3).learn(self.boot_a).learn(self.boot_b)
        attacked, _ = inject.apply(self.boot_a, 'tamper', seed=42)
        findings = base.check(attacked)
        kinds = {f.kind for f in findings}
        self.assertIn('tampered', kinds)

    def test_insert_attack_detected(self):
        base = detect.Baseline(n=3).learn(self.boot_a).learn(self.boot_b)
        attacked, _ = inject.apply(self.boot_a, 'insert', seed=42)
        findings = base.check(attacked)
        kinds = {f.kind for f in findings}
        self.assertIn('unknown', kinds)

    def test_reorder_attack_detected(self):
        base = detect.Baseline(n=3).learn(self.boot_a).learn(self.boot_b)
        attacked, _ = inject.apply(self.boot_a, 'reorder', seed=42)
        findings = base.check(attacked)
        kinds = {f.kind for f in findings}
        self.assertIn('sequence', kinds)
        self.assertNotIn('tampered', kinds)
        self.assertNotIn('unknown', kinds)

    def test_substitute_attack_detected(self):
        base = detect.Baseline(n=3).learn(self.boot_a).learn(self.boot_b)
        attacked, _ = inject.apply(self.boot_a, 'substitute', seed=42)
        findings = base.check(attacked)
        kinds = {f.kind for f in findings}
        self.assertIn('sequence', kinds)
        self.assertNotIn('tampered', kinds)

    def test_boot_stage_classification(self):
        self.assertEqual(stages.classify_path("boot_aggregate"), stages.BootStage.FIRMWARE_UEFI)
        self.assertEqual(stages.classify_path("/boot/vmlinuz-linux"), stages.BootStage.KERNEL_CORE)
        self.assertEqual(stages.classify_path("/init"), stages.BootStage.EARLY_USERSPACE)
        self.assertEqual(stages.classify_path("/bin/systemd"), stages.BootStage.INIT_SYSTEM)
        self.assertEqual(stages.classify_path("/lib/modules/test.ko"), stages.BootStage.KERNEL_MODULES)

    def test_attestation_evidence_generation(self):
        base = detect.Baseline(n=3).learn(self.boot_a)
        findings = base.check(self.boot_a)
        evidence = attest.generate_evidence(self.boot_a, base, findings)
        self.assertEqual(evidence["rats_header"]["type"], "IETF_RATS_EVIDENCE_RFC9334")
        self.assertEqual(evidence["behavioral_attestation"]["trust_rating"], "CLEAN")
        self.assertEqual(evidence["behavioral_attestation"]["overall_anomaly_score"], 0.0)

    def test_benchmark_runner(self):
        boots = [self.boot_a, self.boot_b, self.boot_a]
        report = benchmark.run_benchmark(boots, seed=0)
        self.assertEqual(report["baseline_boots"], 2)
        self.assertIn("scenarios", report)
        self.assertGreaterEqual(report["summary"]["prahari_accuracy"], 0.8)

    def test_pqc_manifest_and_signatures(self):
        if not pqc.supports_pq():
            self.skipTest('ML-DSA OpenSSL support not available in environment')
        with tempfile.TemporaryDirectory() as tmp:
            keydir = Path(tmp) / 'keys'
            bundledir = Path(tmp) / 'bundle'
            pqc.keygen(keydir)
            pqc.sign(self.boot_a, keydir, bundledir)
            results = pqc.verify(bundledir, keydir)
            self.assertTrue(results.get('classical'))
            self.assertTrue(results.get('pq'))


if __name__ == '__main__':
    unittest.main()
