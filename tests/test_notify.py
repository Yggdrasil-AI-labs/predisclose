"""predisclose webhook notifier tests (no network; urlopen is mocked)."""
import json
import unittest
from unittest import mock

from predisclose.engine import Finding
from predisclose import notify as N


def _f():
    return Finding("aws-access-key-id", "high", "a.py", 1, 1, "AKIA1234567890ABCDEF",
                   "msg", "rotate")


class TestPayload(unittest.TestCase):
    def test_slack_default(self):
        p = N.build_payload("slack", "hello", [_f()])
        self.assertEqual(p, {"text": "hello"})

    def test_discord_uses_content_and_caps(self):
        p = N.build_payload("discord", "x" * 5000, [_f()])
        self.assertIn("content", p)
        self.assertLessEqual(len(p["content"]), N.DISCORD_LIMIT)

    def test_generic_includes_findings(self):
        p = N.build_payload("generic", "hello", [_f()])
        self.assertEqual(p["text"], "hello")
        self.assertEqual(p["findings"][0]["rule_id"], "aws-access-key-id")


class TestNotify(unittest.TestCase):
    def test_empty_url_is_noop(self):
        self.assertFalse(N.notify("", "summary", [_f()]))

    def test_posts_json_payload(self):
        captured = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"ok"

        def fake_urlopen(req, timeout=15):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["ct"] = req.headers.get("Content-type")
            return FakeResp()

        with mock.patch.object(N.urllib.request, "urlopen", fake_urlopen):
            ok = N.notify("https://hooks.example.com/x", "found 1", [_f()], style="slack")
        self.assertTrue(ok)
        self.assertEqual(captured["url"], "https://hooks.example.com/x")
        self.assertEqual(captured["body"], {"text": "found 1"})
        self.assertEqual(captured["ct"], "application/json")

    def test_never_raises_on_error(self):
        def boom(req, timeout=15):
            raise OSError("connection refused")

        with mock.patch.object(N.urllib.request, "urlopen", boom):
            self.assertFalse(N.notify("https://x", "s", [_f()]))


if __name__ == "__main__":
    unittest.main()
