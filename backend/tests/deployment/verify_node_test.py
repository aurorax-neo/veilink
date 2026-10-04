import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('verify_node', Path(__file__).resolve().parents[2] / 'tools/verify-node.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(sha256='a' * 64, node_id='client', version='v1.2.3', commit='abc123')
        self.actual = dict(sha256='a' * 64, node_id='client', role='client', version_output='veilink v1.2.3 (abc123)')
        self.node = dict(id='client', role='client', software_version='v1.2.3', software_commit='abc123', revoked=False)

    def test_match(self):
        self.assertTrue(verify.evaluate(self.expected, self.actual, self.node)['verified'])

    def test_self_report_cannot_hide_different_binary(self):
        self.actual['sha256'] = 'b' * 64
        report = verify.evaluate(self.expected, self.actual, self.node)
        self.assertFalse(report['verified'])
        self.assertFalse(report['checks']['binary_sha256'])
        self.assertTrue(report['checks']['reported_version'])

    def test_wrong_identity_version_commit_and_revocation(self):
        for key, value in [('id', 'other'), ('software_version', 'dev'), ('software_commit', 'forged'), ('revoked', True), ('role', 'server')]:
            with self.subTest(key=key):
                self.assertFalse(verify.evaluate(self.expected, self.actual, dict(self.node, **{key: value}))['verified'])
        for key, value in [('node_id', 'other'), ('version_output', 'veilink dev (unknown)'), ('role', 'master')]:
            with self.subTest(key=key):
                self.assertFalse(verify.evaluate(self.expected, dict(self.actual, **{key: value}), self.node)['verified'])

    def test_missing_report_not_verified(self):
        self.assertFalse(verify.evaluate(self.expected, self.actual, {})['verified'])


if __name__ == '__main__':
    unittest.main()
