"""GitHub org/user/repo scanner (the published-surface front-end). Stdlib only.

Read-only: lists public repos + file trees via the GitHub REST API and fetches
file contents from the raw.githubusercontent.com CDN. Unauthenticated by default
(public repos); set GH_TOKEN / GITHUB_TOKEN to raise rate limits or read private
repos you have access to.
"""
import json
import os
import urllib.request

from .engine import scan_text
from .fsscan import is_text, MAX_BYTES, SKIP_DIRS  # reuse text + skip heuristics


def _headers():
    h = {"User-Agent": "predisclose", "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _api(path):
    try:
        req = urllib.request.Request("https://api.github.com" + path, headers=_headers())
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8", "replace")), None
    except Exception as e:
        return None, str(e)


def _raw(full_name, branch, path):
    url = "https://raw.githubusercontent.com/%s/%s/%s" % (
        full_name, branch, urllib.request.quote(path))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "predisclose"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "replace"), None
    except Exception as e:
        return None, str(e)


def list_repos(orgs=None, users=None, repos=None, include_private=False):
    out, errors, seen = [], [], set()

    def _add(meta):
        fn = meta.get("full_name")
        if not fn or fn in seen:
            return
        if meta.get("private") and not include_private:
            return
        if meta.get("archived"):
            return
        seen.add(fn)
        out.append((fn, meta.get("default_branch") or "main"))

    for org in (orgs or []):
        data, err = _api(f"/orgs/{org}/repos?per_page=100&type=public")
        if err or not isinstance(data, list):
            errors.append(f"org {org}: {err or 'unexpected response'}")
            continue
        for m in data:
            _add(m)
    for user in (users or []):
        data, err = _api(f"/users/{user}/repos?per_page=100")
        if err or not isinstance(data, list):
            errors.append(f"user {user}: {err or 'unexpected response'}")
            continue
        for m in data:
            _add(m)
    for fn in (repos or []):
        if fn in seen:
            continue
        meta, err = _api(f"/repos/{fn}")
        if err or not isinstance(meta, dict):
            errors.append(f"repo {fn}: {err or 'unavailable'}")
            continue
        _add(meta)
    return out, errors


def _list_files(full_name, branch):
    data, err = _api(f"/repos/{full_name}/git/trees/{branch}?recursive=1")
    if err or not isinstance(data, dict):
        return [], err or "tree unavailable"
    files = []
    for node in data.get("tree", []):
        if node.get("type") != "blob":
            continue
        path = node.get("path", "")
        if any(seg in SKIP_DIRS for seg in path.split("/")):
            continue
        if not is_text(path):
            continue
        if node.get("size", 0) and node["size"] > MAX_BYTES:
            continue
        files.append(path)
    return files, None


def scan_github(rules, allow, orgs=None, users=None, repos=None,
                include_private=False, ai_hook=None):
    """Returns (findings, repo_count, files_scanned, errors)."""
    repolist, errors = list_repos(orgs, users, repos, include_private)
    findings, files_scanned = [], 0
    for full_name, branch in repolist:
        files, ferr = _list_files(full_name, branch)
        if ferr:
            errors.append(f"tree {full_name}: {ferr}")
            continue
        for path in files:
            text, rerr = _raw(full_name, branch, path)
            if rerr:
                errors.append(f"raw {full_name}/{path}: {rerr}")
                continue
            files_scanned += 1
            label = f"{full_name}:{path}"
            fs = scan_text(text, rules, allow, path=label)
            if ai_hook is not None:
                fs = fs + ai_hook(text, label, fs)
            findings.extend(fs)
    return findings, len(repolist), files_scanned, errors
