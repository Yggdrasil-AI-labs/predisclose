"""Rule loading from a URL (private gist / raw file) via stdlib urllib.

Covers PREDISCLOSE_RULES_URL, --rules <url>, the fail-closed behavior on a bad
URL, and the env-token -> auth-header mapping (offline).
"""
import http.server
import json
import os
import threading
import unittest

from predisclose import engine
from predisclose.engine import (
    _is_url, _rules_auth_headers, load_rules, scan_text,
)

RULES_DOC = {
    "rules": [{"id": "internal-host", "pattern": r"\bacme-[a-z0-9]+\b",
               "severity": "high", "message": "internal hostname",
               "suggestion": "use a public codename"}],
    "allow": ["acme-public"],
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(RULES_DOC).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


class TestRulesUrl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()
        cls.url = f"http://127.0.0.1:{cls.port}/rules.json"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def tearDown(self):
        os.environ.pop("PREDISCLOSE_RULES_URL", None)

    def test_is_url(self):
        self.assertTrue(_is_url("https://x/y.json"))
        self.assertTrue(_is_url("http://x"))
        self.assertFalse(_is_url("/local/path.json"))
        self.assertFalse(_is_url(None))

    def test_rules_from_url_env(self):
        os.environ["PREDISCLOSE_RULES_URL"] = self.url
        rules, allow = load_rules(use_builtin=False)
        self.assertEqual([r.id for r in rules], ["internal-host"])
        self.assertIn("acme-public", allow)
        f = scan_text("ping acme-db01", rules, allow)
        self.assertTrue(any(x.rule_id == "internal-host" for x in f))

    def test_rules_from_url_extra_path(self):
        rules, allow = load_rules(extra_paths=[self.url], use_builtin=False)
        self.assertEqual([r.id for r in rules], ["internal-host"])

    def test_bad_url_raises_oserror(self):
        # CLI catches OSError and exits 2 (fail closed, not silent).
        with self.assertRaises(OSError):
            load_rules(extra_paths=["http://127.0.0.1:1/nope.json"], use_builtin=False)

    def test_auth_headers_explicit_token(self):
        os.environ["PREDISCLOSE_RULES_TOKEN"] = "tok123"
        try:
            h = _rules_auth_headers("https://example.com/x")
            self.assertEqual(h["Authorization"], "Bearer tok123")
        finally:
            os.environ.pop("PREDISCLOSE_RULES_TOKEN", None)

    def test_auth_headers_github_token(self):
        os.environ["GH_TOKEN"] = "ghtok"
        try:
            h = _rules_auth_headers("https://gist.githubusercontent.com/u/i/raw/r")
            self.assertEqual(h["Authorization"], "Bearer ghtok")
        finally:
            os.environ.pop("GH_TOKEN", None)

    def test_auth_headers_gitlab_token(self):
        os.environ["GITLAB_TOKEN"] = "gltok"
        try:
            h = _rules_auth_headers("https://gitlab.com/api/v4/x")
            self.assertEqual(h["PRIVATE-TOKEN"], "gltok")
        finally:
            os.environ.pop("GITLAB_TOKEN", None)

    def test_no_token_no_auth_header(self):
        for v in ("PREDISCLOSE_RULES_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
            os.environ.pop(v, None)
        h = _rules_auth_headers("https://example.com/x")
        self.assertNotIn("Authorization", h)


if __name__ == "__main__":
    unittest.main()
