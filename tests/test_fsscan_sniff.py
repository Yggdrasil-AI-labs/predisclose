"""Extensionless files are content-sniffed, not skipped.

Regression net: predisclose used to skip any file whose name/extension was not
on an allowlist, so canonical extensionless secret files (id_rsa, .s3cfg,
credentials) were silently never scanned. is_text now sniffs content for
extension-less files.
"""
import os
import tempfile
import unittest

from predisclose.fsscan import is_text, scan_paths
from predisclose.engine import load_rules

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...fakekeymaterial...\n-----END RSA PRIVATE KEY-----\n"


class TestSniff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _w(self, name, data, binary=False):
        p = os.path.join(self.d, name)
        with open(p, "wb" if binary else "w") as fh:
            fh.write(data)
        return p

    def test_extensionless_pem_is_text(self):
        self.assertTrue(is_text(self._w("id_rsa", PEM)))

    def test_dotfile_is_text(self):
        self.assertTrue(is_text(self._w(".s3cfg", "secret_key = abc123\n")))

    def test_binary_extensionless_skipped(self):
        self.assertFalse(is_text(self._w("blob", b"\x00\x01\x02\x03PNG", binary=True)))

    def test_unknown_nonempty_ext_still_skipped(self):
        self.assertFalse(is_text(self._w("image.png", b"\x89PNG\r\n\x1a\n", binary=True)))

    def test_scan_finds_key_in_extensionless_file(self):
        self._w("id_rsa", PEM)
        rules, allow = load_rules(scan_root=self.d)
        findings, scanned = scan_paths([self.d], rules, allow, root=self.d)
        self.assertTrue(any(f.rule_id == "private-key-block" for f in findings),
                        "extensionless private key should be scanned and flagged")


if __name__ == "__main__":
    unittest.main()
