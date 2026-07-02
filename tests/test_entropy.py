"""leakguard entropy-detection tests (stdlib unittest)."""
import unittest

from leakguard.engine import load_rules, scan_text
from leakguard.entropy import (EntropyOptions, entropy_findings, shannon_entropy)

# A 38-char token with many distinct characters -> high entropy, no pattern match.
HIGH = "Zk8Qv3Lm9Xr2Tp7Wn5Bc1Yd6Hg4As0UeIoPq"
GIT_SHA = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40-hex, benign


class TestEntropy(unittest.TestCase):
    def setUp(self):
        self.opts = EntropyOptions(enabled=True)

    def test_entropy_value(self):
        self.assertAlmostEqual(shannon_entropy("aaaa"), 0.0)
        self.assertGreater(shannon_entropy(HIGH), 4.0)

    def test_flags_high_entropy_token(self):
        f = entropy_findings("value: " + HIGH, set(), "f.txt", self.opts, [])
        self.assertTrue(any(x.match == HIGH for x in f))

    def test_low_entropy_prose_not_flagged(self):
        f = entropy_findings("the quick brown fox jumps over the lazy dog again",
                             set(), "f.txt", self.opts, [])
        self.assertEqual(f, [])

    def test_disabled_is_noop(self):
        off = EntropyOptions(enabled=False)
        self.assertEqual(entropy_findings("x " + HIGH, set(), "f.txt", off, []), [])

    def test_lockfile_skipped(self):
        f = entropy_findings("x " + HIGH, set(), "yarn.lock", self.opts, [])
        self.assertEqual(f, [])

    def test_allow_list_honored(self):
        f = entropy_findings("x " + HIGH, {HIGH}, "f.txt", self.opts, [])
        self.assertEqual(f, [])

    def test_git_sha_not_flagged(self):
        f = entropy_findings("commit " + GIT_SHA, set(), "CHANGELOG.md", self.opts, [])
        self.assertFalse(any(x.match == GIT_SHA for x in f))

    def test_threshold_tunable(self):
        strict = EntropyOptions(enabled=True, b64_threshold=6.0)
        self.assertEqual(entropy_findings("v " + HIGH, set(), "f.txt", strict, []), [])

    def test_overlap_with_pattern_match_skipped(self):
        rules, allow = load_rules()
        text = "key AKIA1234567890ABCDEF"
        rf = scan_text(text, rules, allow, path="f.txt")
        ef = entropy_findings(text, allow, "f.txt", self.opts, rf)
        self.assertFalse(any("AKIA" in x.match for x in ef))


    def test_bare_uuid_not_flagged(self):
        # request/trace ids in logs; the real UUID secret (Heroku) is proximity turf
        f = entropy_findings("request_id=c0d0d1d5-ff13-48d6-bc6d-049e74011858",
                             set(), "app.log", self.opts, [])
        self.assertEqual(f, [])

    def test_key_value_not_glued_by_equals(self):
        # = joins key and value only as base64 TRAILING padding, never mid-token;
        # an env assignment of two low-entropy words must not flag as one token
        f = entropy_findings("SERVICE_NAME=scanner-stress-service",
                             set(), ".env", self.opts, [])
        self.assertEqual(f, [])

    def test_trailing_padding_kept(self):
        # an 88-char base64 key ending == (azure-storage shape) must still flag
        import base64, os
        tok = base64.b64encode(os.urandom(64)).decode()
        self.assertTrue(tok.endswith("="))
        f = entropy_findings("k = " + tok, set(), "f.txt", self.opts, [])
        self.assertTrue(any(x.match == tok for x in f))


    def test_actions_ref_not_flagged(self):
        # CI action refs are 3+ short dictionary segments, not base64
        f = entropy_findings("      uses: github/codeql-action/upload-sarif@v3",
                             set(), "ci.yml", self.opts, [])
        self.assertEqual(f, [])

    def test_url_path_after_domain_not_flagged(self):
        f = entropy_findings(
            "see https://github.com/Example-Org-Name/some-repo-name/issues",
            set(), "README.md", self.opts, [])
        self.assertEqual(f, [])


if __name__ == "__main__":
    unittest.main()
