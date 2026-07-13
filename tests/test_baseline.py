"""predisclose baseline tests."""
import os
import tempfile
import unittest

from predisclose.engine import Finding
from predisclose.baseline import fingerprint, load_baseline, write_baseline, filter_new


def f(rule="aws-access-key-id", path="a.py", match="AKIAxxxxxxxxxxxxxxxx", line=1):
    return Finding(rule, "high", path, line, 1, match, "m", "s")


class TestBaseline(unittest.TestCase):
    def test_fingerprint_stable_across_line_moves(self):
        self.assertEqual(fingerprint(f(line=1)), fingerprint(f(line=999)))

    def test_fingerprint_changes_with_match_or_path(self):
        self.assertNotEqual(fingerprint(f(match="AAA")), fingerprint(f(match="BBB")))
        self.assertNotEqual(fingerprint(f(path="a.py")), fingerprint(f(path="b.py")))

    def test_write_does_not_store_secret(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bl.json")
            n = write_baseline(p, [f(match="S3CRETvalue123")])
            self.assertEqual(n, 1)
            with open(p, encoding="utf-8") as fh:
                self.assertNotIn("S3CRETvalue123", fh.read())

    def test_filter_suppresses_known_reports_new(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bl.json")
            write_baseline(p, [f(match="OLD")])
            base, err = load_baseline(p)
            self.assertIsNone(err)
            new = filter_new([f(match="OLD"), f(match="NEW")], base)
            self.assertEqual([x.match for x in new], ["NEW"])

    def test_missing_baseline_is_empty_not_error(self):
        base, err = load_baseline(os.path.join(tempfile.gettempdir(), "no-such-lg.json"))
        self.assertEqual(base, set())
        self.assertIsNone(err)

    def test_corrupt_baseline_reports_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w") as fh:
                fh.write("{not json")
            base, err = load_baseline(p)
            self.assertIsNotNone(err)


if __name__ == "__main__":
    unittest.main()
