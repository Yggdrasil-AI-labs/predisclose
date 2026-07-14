"""Regression net for the single-file zipapp build (scripts/build_pyz.py).

Guards the exit-code propagation bug: zipapp's own ``main="pkg:fn"`` generator
calls the entry function but discards its return value, so the archive would
exit 0 even on findings and silently never gate CI or block a commit. The build
script ships its own __main__.py to fix that; these tests lock it in.
"""
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDER = os.path.join(ROOT, "scripts", "build_pyz.py")


def _build(dest):
    subprocess.run([sys.executable, BUILDER, "-o", dest],
                   check=True, capture_output=True)


def _scan(pyz, path):
    return subprocess.run([sys.executable, pyz, "scan", path],
                          capture_output=True).returncode


class TestPyzBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pyz = os.path.join(self.tmp.name, "predisclose.pyz")
        _build(self.pyz)

    def tearDown(self):
        self.tmp.cleanup()

    def test_builds(self):
        self.assertTrue(os.path.getsize(self.pyz) > 0)

    def test_version_runs_from_archive(self):
        r = subprocess.run([sys.executable, self.pyz, "--version"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("predisclose", r.stdout.lower() + r.stderr.lower())

    def test_gates_on_findings(self):
        d = os.path.join(self.tmp.name, "dirty")
        os.makedirs(d)
        with open(os.path.join(d, "leak.txt"), "w") as fh:
            fh.write("key = AKIAIOSFODNN7EXAMPLE\n")
        # Must exit 1 so a CI gate / pre-commit hook actually blocks.
        self.assertEqual(_scan(self.pyz, d), 1)

    def test_clean_exit_zero(self):
        d = os.path.join(self.tmp.name, "clean")
        os.makedirs(d)
        with open(os.path.join(d, "ok.txt"), "w") as fh:
            fh.write("nothing sensitive here\n")
        self.assertEqual(_scan(self.pyz, d), 0)


if __name__ == "__main__":
    unittest.main()
