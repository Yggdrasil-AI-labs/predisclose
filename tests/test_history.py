"""predisclose git-history scan tests (stdlib unittest; builds throwaway repos)."""
import os
import subprocess
import tempfile
import unittest

from predisclose.engine import load_rules
from predisclose.history import scan_history, is_git_repo

SECRET = "AKIA1234567890ABCDEF"


def _run(args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def _write(d, name, content):
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        fh.write(content)


class TestHistory(unittest.TestCase):
    def _init_repo(self, d):
        _run(["git", "init", "-q"], d)
        _run(["git", "config", "user.email", "t@example.com"], d)
        _run(["git", "config", "user.name", "tester"], d)
        _run(["git", "config", "commit.gpgsign", "false"], d)

    def test_not_a_repo(self):
        rules, allow = load_rules()
        with tempfile.TemporaryDirectory() as d:
            _, _, _, err = scan_history(rules, allow, cwd=d)
            self.assertIsNotNone(err)
            self.assertFalse(is_git_repo(d))

    def test_finds_secret_removed_in_later_commit(self):
        rules, allow = load_rules()
        with tempfile.TemporaryDirectory() as d:
            self._init_repo(d)
            _write(d, "config.py", "aws = '%s'\n" % SECRET)
            _run(["git", "add", "."], d)
            _run(["git", "commit", "-qm", "add"], d)
            _write(d, "config.py", "aws = 'REDACTED'\n")
            _run(["git", "add", "."], d)
            _run(["git", "commit", "-qm", "remove"], d)

            findings, commits, files, err = scan_history(rules, allow, cwd=d)
            self.assertIsNone(err)
            self.assertEqual(commits, 2)
            ids = {f.rule_id for f in findings}
            self.assertIn("aws-access-key-id", ids)
            self.assertTrue(all(f.commit for f in findings))

    def test_dedup_across_commits(self):
        rules, allow = load_rules()
        with tempfile.TemporaryDirectory() as d:
            self._init_repo(d)
            _write(d, "a.py", "k = '%s'\n" % SECRET)
            _run(["git", "add", "."], d)
            _run(["git", "commit", "-qm", "c1"], d)
            # touch a.py again, secret stays on line 1
            _write(d, "a.py", "k = '%s'\n# note\n" % SECRET)
            _run(["git", "add", "."], d)
            _run(["git", "commit", "-qm", "c2"], d)

            findings, _, _, err = scan_history(rules, allow, cwd=d)
            self.assertIsNone(err)
            aws = [f for f in findings if f.rule_id == "aws-access-key-id"]
            self.assertEqual(len(aws), 1)

    def test_since_narrows_range(self):
        rules, allow = load_rules()
        with tempfile.TemporaryDirectory() as d:
            self._init_repo(d)
            _write(d, "clean.py", "x = 1\n")
            _run(["git", "add", "."], d)
            _run(["git", "commit", "-qm", "base"], d)
            head0 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d,
                                   capture_output=True, text=True).stdout.strip()
            _write(d, "leak.py", "k = '%s'\n" % SECRET)
            _run(["git", "add", "."], d)
            _run(["git", "commit", "-qm", "leak"], d)

            findings, commits, _, err = scan_history(rules, allow, since=head0, cwd=d)
            self.assertIsNone(err)
            self.assertEqual(commits, 1)
            self.assertTrue(any(f.rule_id == "aws-access-key-id" for f in findings))


if __name__ == "__main__":
    unittest.main()
