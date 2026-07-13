"""Regression: a secret far along a single long line must still be found.

Lines are capped (a DoS guard), but the cap must be high enough that real-world
long lines (minified JS, single-line JSON, long .env values) don't hide secrets
past the old 4000-char limit.
"""
import unittest

from predisclose.engine import load_rules, scan_text
from predisclose.entropy import EntropyOptions, entropy_findings


class TestLongLine(unittest.TestCase):
    def setUp(self):
        self.rules, self.allow = load_rules()

    def test_secret_far_along_one_line(self):
        text = "x" * 50000 + " AKIAIOSFODNN7EXAMPLE"
        ids = {f.rule_id for f in scan_text(text, self.rules, self.allow)}
        self.assertIn("aws-access-key-id", ids)

    def test_entropy_far_along_one_line(self):
        token = "aB3xK9mP2qR7tL5wZ8vN1cD4fG6hJ0sYzQ"
        text = "y" * 50000 + " " + token
        opts = EntropyOptions(enabled=True)
        matches = [f.match for f in entropy_findings(text, set(), "f.txt", opts, [])]
        self.assertIn(token, matches)


if __name__ == "__main__":
    unittest.main()
