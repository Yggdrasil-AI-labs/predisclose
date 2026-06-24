"""Adversarial acceptance suite — runs in CI on every push.

Locks in three guarantees: recall (every built-in detector fires), precision
(decoys that resemble secrets stay silent), and entropy thresholding. This is the
committed version of the lab stress harness.
"""
import unittest

from leakguard.engine import load_rules, scan_text
from leakguard.entropy import EntropyOptions, entropy_findings
from leakguard.patterns import BUILTIN_PATTERNS

_A = "a"
# rule_id -> a sample that MUST trigger it.
POSITIVES = {
    "aws-access-key-id":          "key=AKIAIOSFODNN7EXAMPLE",
    "gcp-api-key":                "k=AIza" + "B" * 35,
    "gcp-service-account":        '"type": "service_account"',
    "azure-storage-key":          "AccountKey=" + _A * 86 + "==",
    "azure-sas-token":            "url?sig=" + "A" * 50 + "=",
    "digitalocean-token":         "dop_v1_" + _A * 64,
    "github-token":               "tok ghp_" + _A * 36,
    "github-pat-fine-grained":    "github_pat_" + _A * 82,
    "gitlab-pat":                 "glpat-" + _A * 20,
    "npm-access-token":           "npm_" + _A * 36,
    "pypi-token":                 "pypi-AgEIcHlwaS5vcmc" + _A * 55,
    "anthropic-api-key":          "sk-ant-" + _A * 30,
    "openai-api-key":             "sk-" + _A * 40,
    "huggingface-token":          "hf_" + _A * 34,
    "stripe-secret-key":          "sk_live_" + _A * 20,
    "twilio-account-sid":         "AC" + _A * 32,
    "twilio-api-key":             "SK" + _A * 32,
    "sendgrid-api-key":           "SG." + _A * 22 + "." + _A * 43,
    "mailchimp-api-key":          _A * 32 + "-us12",
    "google-oauth-client-secret": "GOCSPX-" + _A * 24,
    "square-access-token":        "sq0atp-" + _A * 22,
    "shopify-token":              "shpat_" + _A * 32,
    "postman-api-key":            "PMAK-" + _A * 24 + "-" + _A * 34,
    "notion-token":               "secret_" + _A * 43,
    "dropbox-token":              "sl." + _A * 130,
    "telegram-bot-token":         "12345678:" + _A * 35,
    "slack-token":                "xoxb-123456789012-abcdefghij",
    "slack-webhook":              "https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24,
    "discord-webhook":            "https://discord.com/api/webhooks/123456789012345678/" + _A * 30,
    "slack-app-token":            "xapp-1-ABCDEF-123456-abcdef",
    "sentry-dsn":                 "https://" + _A * 32 + "@o0.ingest.sentry.io/1",
    "databricks-pat":             "dapi" + _A * 32,
    "newrelic-api-key":           "NRAK-" + "A" * 27,
    "gcp-oauth-refresh-token":    "1//" + _A * 40,
    "linear-api-key":             "lin_api_" + _A * 40,
    "doppler-token":              "dp.pt." + _A * 40,
    "grafana-service-account":    "glsa_" + _A * 32 + "_abcdef12",
    "mailgun-api-key":            "key-" + _A * 32,
    "pulumi-token":               "pul-" + _A * 40,
    "terraform-cloud-token":      _A * 14 + ".atlasv1." + _A * 60,
    "hashicorp-vault-token":      "hvs." + _A * 24,
    "npmrc-auth-token":           "_authToken=" + _A * 24,
    "atlassian-api-token":        "ATATT3" + _A * 40,
    "firebase-fcm-key":           "AAAA" + "abcdefg" + ":" + _A * 120,
    "newrelic-license-key":       "NRAL-" + _A * 40,
    "okta-token":                 "00" + _A * 40,
    "azure-ad-client-secret":     "abc~" + _A * 35,
    "docker-config-auth":         '"auth": "' + _A * 40 + '"',
    "jdbc-url-password":          "jdbc:postgresql://h:5432/db?user=x&password=secret12",
    "netrc-credentials":          "machine h.example login usr password s3cretpass",
    "private-key-block":          "-----BEGIN RSA PRIVATE KEY-----",
    "jwt":                        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N",
    "db-connection-uri":          "postgres://user:pass@dbhost:5432/app",
    "url-basic-auth":             "https://user:pass@internalhost.net/path",
    "generic-assignment-secret":  'password = "supersecret123"',
    "authorization-header":       "Authorization: Bearer abcd1234efgh5678ijkl",
    "private-ip":                 "host 10.1.2.3 here",
    "cgnat-ip":                   "tail 100.64.0.1 here",
    "tailscale-magicdns":         "box host-1.example-tail.ts.net up",
    "email-address":              "reach person@realcompany.io now",
}

# Decoys that MUST produce zero findings.
CLEAN = {
    "rfc5737":      "docs use 203.0.113.5 and 192.0.2.1 and 198.51.100.7",
    "example-mail": "a@example.com b@example.org c@example.net",
    "version-3oct": "version v1.2.3 release 10.0.0 build x",
    "version-lead": "framework 1.10.0.0 changelog",
    "uuid":         "id 550e8400-e29b-41d4-a716-446655440000",
    "lower-aws":    "lowercase akiaiosfodnn7example is not a key",
    "git-sha":      "commit da39a3ee5e6b4b0d3255bfef95601890afd80709 merged",
    "prose":        "a perfectly ordinary sentence with nothing sensitive in it",
    "doc-host":     "see https://app.example.com/path for details",
}


class TestRecall(unittest.TestCase):
    def setUp(self):
        self.rules, self.allow = load_rules()

    def _ids(self, text):
        return {f.rule_id for f in scan_text(text, self.rules, self.allow)}

    def test_every_builtin_has_a_sample(self):
        missing = {p[0] for p in BUILTIN_PATTERNS} - set(POSITIVES)
        self.assertEqual(missing, set(), f"builtins with no positive sample: {missing}")

    def test_all_builtins_fire(self):
        for rid, sample in POSITIVES.items():
            self.assertIn(rid, self._ids(sample), f"{rid} not flagged in {sample!r}")

    def test_adversarial_placements(self):
        self.assertIn("aws-access-key-id", self._ids("x" * 5000 + " AKIAIOSFODNN7EXAMPLE"))
        self.assertLessEqual({"aws-access-key-id", "private-ip"},
                             self._ids("AKIAIOSFODNN7EXAMPLE\r\n10.1.2.3\r\n"))
        self.assertLessEqual({"aws-access-key-id", "stripe-secret-key"},
                             self._ids("a=AKIAIOSFODNN7EXAMPLE b=sk_live_" + _A * 20))


class TestPrecision(unittest.TestCase):
    def setUp(self):
        self.rules, self.allow = load_rules()

    def test_decoys_are_clean(self):
        for name, text in CLEAN.items():
            got = {f.rule_id for f in scan_text(text, self.rules, self.allow)}
            self.assertEqual(got, set(), f"false positive in {name!r}: {got}")


class TestEntropyDiscipline(unittest.TestCase):
    def setUp(self):
        self.rules, self.allow = load_rules()
        self.opts = EntropyOptions(enabled=True)
        self.high = "aB3xK9mP2qR7tL5wZ8vN1cD4fG6hJ0sYzQ"

    def test_flags_real_high_entropy(self):
        out = entropy_findings("seed " + self.high, set(), "f.txt", self.opts, [])
        self.assertTrue(any(f.match == self.high for f in out))

    def test_skips_false_friends(self):
        self.assertEqual(entropy_findings("x " + self.high, set(), "yarn.lock", self.opts, []), [])
        self.assertEqual(entropy_findings("sha da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                          set(), "c.md", self.opts, []), [])
        self.assertEqual(entropy_findings("x " + self.high, {self.high}, "f.txt", self.opts, []), [])
        self.assertEqual(entropy_findings("x " + _A * 40, set(), "f.txt", self.opts, []), [])

    def test_no_double_report_of_pattern_match(self):
        rf = scan_text("AKIAIOSFODNN7EXAMPLE", self.rules, self.allow, path="f.txt")
        ef = entropy_findings("AKIAIOSFODNN7EXAMPLE", self.allow, "f.txt", self.opts, rf)
        self.assertFalse(any("AKIA" in f.match for f in ef))


if __name__ == "__main__":
    unittest.main()
