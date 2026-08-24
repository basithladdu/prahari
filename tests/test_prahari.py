import tempfile
import unittest
from pathlib import Path

from prahari import detect, inject, parse, pqc, tokens


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
