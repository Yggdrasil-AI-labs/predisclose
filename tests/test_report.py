"""predisclose report (Markdown / text summary) tests."""
import unittest

from predisclose.engine import Finding
from predisclose.report import build_markdown, build_summary_text

SECRET = "AKIA1234567890ABCDEF"


def _f(rule="aws-access-key-id", sev="high", path="a.py", line=1, col=1, match=SECRET):
    return Finding(rule, sev, path, line, col, match, "msg", "do the thing")


class TestReport(unittest.TestCase):
    def test_markdown_clean(self):
        md = build_markdown([], 12, "filesystem")
        self.assertIn("clean", md)
        self.assertIn("12 file(s)", md)

    def test_markdown_table_and_redaction(self):
        md = build_markdown([_f()], 3, "filesystem", fail_on="medium", blocking=1)
        self.assertIn("| Severity | Rule | Location | Match | Suggestion |", md)
        self.assertIn("aws-access-key-id", md)
        self.assertIn("a.py:1:1", md)
        self.assertIn("failing", md)
        # secret must be redacted, never present verbatim
        self.assertNotIn(SECRET, md)

    def test_markdown_blocking_vs_nonblocking(self):
        low = _f(rule="email-address", sev="low", match="x@contoso.com")
        md = build_markdown([low], 1, "filesystem", fail_on="medium", blocking=0)
        self.assertIn("below `medium`", md)

    def test_markdown_escapes_pipes(self):
        md = build_markdown([_f(match="a|b|c12345")], 1, "filesystem")
        # raw unescaped pipes would break the table; ensure escaping happened
        self.assertIn("\\|", md)

    def test_summary_text(self):
        txt = build_summary_text([_f(), _f(rule="jwt", sev="medium")], 2, "filesystem")
        self.assertIn("2 finding(s)", txt)
        self.assertIn("[HIGH] aws-access-key-id", txt)
        self.assertNotIn(SECRET, txt)

    def test_summary_text_truncates(self):
        many = [_f(line=i) for i in range(30)]
        txt = build_summary_text(many, 1, "filesystem", limit=5)
        self.assertIn("and 25 more", txt)

    def test_summary_text_clean(self):
        self.assertIn("clean", build_summary_text([], 4, "filesystem"))


if __name__ == "__main__":
    unittest.main()
