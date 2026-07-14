"""Unit tests for the GitHub scanner path (network mocked). Covers the
private-repo support: CDN-first fetch, authenticated Contents-API fallback, and
repo-listing type selection."""
import base64
from predisclose import github_scan as gs


class _Resp:
    def __init__(self, data):
        self._d = data
    def read(self):
        return self._d
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def test_raw_public_uses_cdn(monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["url"] = req.full_url
        return _Resp(b"public content")

    monkeypatch.setattr(gs.urllib.request, "urlopen", fake_urlopen)
    text, err = gs._raw("owner/repo", "main", "a.py")
    assert err is None and text == "public content"
    assert "raw.githubusercontent.com" in seen["url"]


def test_raw_no_token_does_not_hit_api(monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def fake_urlopen(req, timeout=0):
        raise Exception("HTTP Error 404: Not Found")

    def boom(path):
        raise AssertionError("Contents API must not be called without a token")

    monkeypatch.setattr(gs.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(gs, "_api", boom)
    text, err = gs._raw("owner/repo", "main", "a.py")
    assert text is None and err is not None


def test_raw_private_falls_back_to_api(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "dummy")

    def fake_urlopen(req, timeout=0):
        raise Exception("HTTP Error 404: Not Found")  # CDN 404s on private

    payload = {"encoding": "base64",
               "content": base64.b64encode(b"private\nsecret").decode()}
    monkeypatch.setattr(gs.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(gs, "_api", lambda path: (payload, None))
    text, err = gs._raw("owner/priv", "main", "a.py")
    assert err is None and text == "private\nsecret"


def test_raw_api_unexpected_response(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "dummy")
    monkeypatch.setattr(gs.urllib.request, "urlopen",
                        lambda req, timeout=0: (_ for _ in ()).throw(Exception("404")))
    monkeypatch.setattr(gs, "_api", lambda path: ({"encoding": "none"}, None))
    text, err = gs._raw("owner/priv", "main", "a.py")
    assert text is None and "unexpected" in err


def test_list_repos_type_all_when_private(monkeypatch):
    seen = []
    monkeypatch.setattr(gs, "_api", lambda path: (seen.append(path) or [], None))
    gs.list_repos(orgs=["acme"], include_private=True)
    assert any("type=all" in p for p in seen), seen


def test_list_repos_type_public_by_default(monkeypatch):
    seen = []
    monkeypatch.setattr(gs, "_api", lambda path: (seen.append(path) or [], None))
    gs.list_repos(orgs=["acme"])
    assert any("type=public" in p for p in seen), seen
