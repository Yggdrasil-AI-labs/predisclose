"""predisclose live-verification tests (no network; urlopen is mocked)."""
import unittest
import urllib.error
from unittest import mock

from predisclose.engine import Finding
from predisclose import verify as V


class FakeResp:
    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self._b = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getcode(self):
        return self.status

    def read(self):
        return self._b


def f(rule, match="tok"):
    return Finding(rule, "high", "a.py", 1, 1, match, "m", "s")


def _patch(resp_or_exc):
    def fake(req, timeout=10):
        if isinstance(resp_or_exc, Exception):
            raise resp_or_exc
        return resp_or_exc
    return mock.patch.object(V.urllib.request, "urlopen", fake)


class TestVerify(unittest.TestCase):
    def test_active_on_200(self):
        with _patch(FakeResp(200)):
            self.assertEqual(V._github("x"), "active")

    def test_inactive_on_401(self):
        with _patch(urllib.error.HTTPError("u", 401, "no", {}, None)):
            self.assertEqual(V._github("x"), "inactive")

    def test_unknown_on_500(self):
        with _patch(urllib.error.HTTPError("u", 500, "err", {}, None)):
            self.assertEqual(V._github("x"), "unknown")

    def test_unknown_on_network_error(self):
        with _patch(OSError("connection refused")):
            self.assertEqual(V._stripe("x"), "unknown")

    def test_slack_ok_json_true_false(self):
        with _patch(FakeResp(200, b'{"ok":true}')):
            self.assertEqual(V._slack("x"), "active")
        with _patch(FakeResp(200, b'{"ok":false}')):
            self.assertEqual(V._slack("x"), "inactive")

    def test_verify_findings_annotates_dedupes_skips_unsupported(self):
        calls = {"n": 0}

        def one(req, timeout=10):
            calls["n"] += 1
            return FakeResp(200)

        findings = [f("github-token", "T"), f("github-token", "T"),
                    f("private-ip", "10.0.0.1")]
        with mock.patch.object(V.urllib.request, "urlopen", one):
            counts = V.verify_findings(findings)
        self.assertEqual(calls["n"], 1)            # identical (rule,match) -> one call
        self.assertEqual(findings[0].verified, "active")
        self.assertEqual(findings[2].verified, "")  # unsupported type left untouched
        self.assertEqual(counts["active"], 2)

    def test_supported_set(self):
        self.assertIn("openai-api-key", V.supported())
        self.assertIn("github-token", V.supported())


if __name__ == "__main__":
    unittest.main()
