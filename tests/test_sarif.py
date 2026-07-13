"""predisclose SARIF output tests (stdlib unittest)."""
import json
import unittest

from predisclose.engine import Finding
from predisclose.sarif import build_sarif, redact

SECRET = "AKIA1234567890ABCDEF"


class TestSarif(unittest.TestCase):
    def test_shape(self):
        f = Finding(rule_id="aws-access-key-id", severity="high", path="a.py",
                    line=3, column=5, match=SECRET,
                    message="AWS access key id", suggestion="rotate")
        doc = build_sarif([f], tool_version="0.2.0")
        self.assertEqual(doc["version"], "2.1.0")
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "predisclose")
        self.assertEqual(driver["version"], "0.2.0")
        self.assertEqual(len(driver["rules"]), 1)
        res = doc["runs"][0]["results"][0]
        self.assertEqual(res["ruleId"], "aws-access-key-id")
        self.assertEqual(res["level"], "error")
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "a.py")
        self.assertEqual(loc["region"]["startLine"], 3)
        self.assertEqual(loc["region"]["startColumn"], 5)

    def test_secret_is_redacted_everywhere(self):
        f = Finding("aws-access-key-id", "high", "a.py", 1, 1, SECRET, "m", "s")
        self.assertNotIn(SECRET, json.dumps(build_sarif([f])))

    def test_redact(self):
        self.assertEqual(redact("abc"), "a***")
        self.assertNotIn("234567890ABCDE", redact(SECRET))

    def test_rule_dedup_and_index(self):
        f1 = Finding("r1", "high", "a", 1, 1, "xxxxxxxx", "m", "s")
        f2 = Finding("r1", "high", "b", 2, 1, "yyyyyyyy", "m", "s")
        doc = build_sarif([f1, f2])
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(doc["runs"][0]["results"][1]["ruleIndex"], 0)

    def test_commit_surfaced(self):
        f = Finding("r1", "high", "a", 1, 1, "xxxxxxxx", "m", "s", commit="abc1234567")
        res = build_sarif([f])["runs"][0]["results"][0]
        self.assertEqual(res["properties"]["commit"], "abc1234567")
        self.assertIn("abc1234567", res["message"]["text"])


if __name__ == "__main__":
    unittest.main()
