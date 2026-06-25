"""leakguard keyword-proximity tests."""
import unittest

from leakguard.engine import Finding
from leakguard.proximity import proximity_findings, KEYWORD_RULES

# keyword -> a synthetic token of the right shape, per rule_id
SAMPLES = {
    "datadog-access-token": ("datadog", "a" * 40),
    "algolia-api-key": ("algolia", "a" * 32),
    "cloudflare-global-api-key": ("cloudflare", "a" * 37),
    "cloudflare-api-token": ("cloudflare", "a" * 40),
    "heroku-api-key": ("heroku", "12345678-1234-1234-1234-123456789012"),
    "jfrog-api-key": ("jfrog", "a" * 73),
    "jfrog-identity-token": ("artifactory", "a" * 64),
    "facebook-app-secret": ("facebook", "a" * 32),
    "mapbox-token": ("mapbox", "pk." + "a" * 60 + "." + "a" * 22),
    "twitter-api-secret": ("twitter", "a" * 50),
    "twitter-access-secret": ("twitter", "a" * 45),
}


class TestProximity(unittest.TestCase):
    def test_every_rule_has_a_sample(self):
        self.assertEqual({r[0] for r in KEYWORD_RULES}, set(SAMPLES))

    def test_each_rule_fires_with_keyword(self):
        for rid, (kw, tok) in SAMPLES.items():
            text = f'{kw}_secret = "{tok}"'
            ids = {f.rule_id for f in proximity_findings(text)}
            self.assertIn(rid, ids, f"{rid} did not fire on {text!r}")

    def test_token_without_keyword_is_silent(self):
        # a bare 40-char token with no provider keyword must NOT be flagged
        self.assertEqual(proximity_findings('value = "' + "a" * 40 + '"'), [])

    def test_window_enforced(self):
        text = "datadog" + " " * 80 + "a" * 40  # keyword too far from token
        hits = [f for f in proximity_findings(text) if f.rule_id == "datadog-access-token"]
        self.assertEqual(hits, [])

    def test_allow_list_honored(self):
        tok = "a" * 40
        self.assertEqual(proximity_findings(f'datadog="{tok}"', allow={tok}), [])

    def test_no_double_report_when_pattern_covers_span(self):
        tok = "a" * 40
        text = f'datadog="{tok}"'
        col = text.index(tok) + 1
        rf = [Finding("some-rule", "high", "f", 1, col, tok, "m", "s")]
        out = proximity_findings(text, rule_findings=rf)
        self.assertFalse(any(f.match == tok for f in out))


if __name__ == "__main__":
    unittest.main()
