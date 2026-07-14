"""predisclose scan engine: load rules, scan text, return findings. Stdlib only.

Rule sources, merged in this order:
  1. built-in generic patterns (patterns.py) unless disabled
  2. any files passed via --rules (JSON)
  3. an auto-loaded private file `.predisclose.local.json` from the scan root or
     $PREDISCLOSE_RULES, if present (this is where org-specific patterns live; it
     should be gitignored and NEVER committed)

Private rules file format (JSON):
  {
    "rules": [
      {"id": "internal-host", "pattern": "\\\\bacme-[a-z0-9]+\\\\b",
       "severity": "high", "message": "internal hostname",
       "suggestion": "use a public codename", "flags": "i"}
    ],
    "allow": ["acme-public-handle", "203.0.113.5"]
  }
`allow` entries are literal strings; any match equal to an allow entry is dropped
(e.g. public codenames that look like internal names but are intentionally public).

An optional "entropy" object in the same file configures opt-in high-entropy
detection (see predisclose/entropy.py); it is ignored here.
"""
import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict

from .patterns import builtin_rules

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
LOCAL_RULES_NAME = ".predisclose.local.json"


@dataclass
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    column: int
    match: str
    message: str
    suggestion: str
    commit: str = ""  # short SHA when produced by a git-history scan; "" otherwise
    verified: str = ""  # set by --verify: active | inactive | unknown; "" if not checked

    def as_dict(self):
        return asdict(self)


class Rule:
    __slots__ = ("id", "regex", "severity", "message", "suggestion", "anchors")

    def __init__(self, rid, pattern, severity="high", message="", suggestion="",
                 flags="", anchors=None):
        self.id = rid
        self.regex = re.compile(pattern, _compile_flags(flags))
        self.severity = severity if severity in SEVERITY_ORDER else "medium"
        self.message = message
        self.suggestion = suggestion
        # Lowercase literal substrings, at least one of which MUST appear in any
        # match. Used as a cheap prefilter: skip the regex when none are present.
        # Empty -> always run (sound fallback). Anchors must be guaranteed
        # substrings of every match or matches will be missed.
        self.anchors = tuple(a.lower() for a in anchors) if anchors else ()


def _compile_flags(flags):
    f = 0
    if not flags:
        return f
    s = flags.lower()
    if "i" in s:
        f |= re.IGNORECASE
    if "m" in s:
        f |= re.MULTILINE
    if "s" in s:
        f |= re.DOTALL
    return f


def _rules_from_dicts(items):
    out = []
    for r in items:
        try:
            out.append(Rule(r["id"], r["pattern"], r.get("severity", "high"),
                            r.get("message", ""), r.get("suggestion", ""),
                            r.get("flags", ""), r.get("anchor")))
        except (KeyError, re.error) as e:
            raise ValueError(f"bad rule {r.get('id', r)!r}: {e}")
    return out


def _load_rules_text(text):
    data = json.loads(text)
    if isinstance(data, list):
        return _rules_from_dicts(data), []
    return _rules_from_dicts(data.get("rules", [])), list(data.get("allow", []))


def _load_rules_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return _load_rules_text(fh.read())


def _is_url(s):
    return isinstance(s, str) and (s.startswith("http://") or s.startswith("https://"))


def _rules_auth_headers(url):
    """Best-effort auth for a private rule URL, from env tokens. Stdlib only.

    PREDISCLOSE_RULES_TOKEN wins if set (a Bearer token, any host). Otherwise a
    GitHub host picks up GH_TOKEN / GITHUB_TOKEN, so you can point at a private
    gist or raw repo file with a token already in the environment. No token is
    required for a public or secret-URL gist.
    """
    headers = {"User-Agent": "predisclose"}
    tok = os.environ.get("PREDISCLOSE_RULES_TOKEN")
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
        return headers
    host = urllib.parse.urlparse(url).netloc.lower()
    if "github" in host:
        gh = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if gh:
            headers["Authorization"] = f"Bearer {gh}"
    return headers


def _fetch_rules_url(url, timeout=15):
    """Fetch a rules JSON document over HTTP(S) with stdlib urllib."""
    req = urllib.request.Request(url, headers=_rules_auth_headers(url))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def load_rules(extra_paths=None, use_builtin=True, scan_root="."):
    """Returns (rules, allow_set). Auto-loads a private local rules file if found."""
    rules, allow = [], []
    if use_builtin:
        rules += _rules_from_dicts(builtin_rules())
    for p in (extra_paths or []):
        r, a = (_load_rules_text(_fetch_rules_url(p)) if _is_url(p)
                else _load_rules_file(p))
        rules += r
        allow += a
    # a private rules URL (e.g. a private gist or raw repo file), fetched with
    # stdlib urllib; lets a small team share one rules doc without committing it.
    url_env = os.environ.get("PREDISCLOSE_RULES_URL")
    if url_env:
        r, a = _load_rules_text(_fetch_rules_url(url_env))
        rules += r
        allow += a
    # auto-load private local config (gitignored, org-specific, never committed)
    candidates = []
    env_path = os.environ.get("PREDISCLOSE_RULES")
    if env_path:
        candidates.append(env_path)
    candidates.append(os.path.join(scan_root, LOCAL_RULES_NAME))
    for c in candidates:
        if c and os.path.isfile(c):
            r, a = _load_rules_file(c)
            rules += r
            allow += a
    return rules, set(allow)


def scan_text(text, rules, allow=None, path="<text>", max_line=200_000):
    allow = allow or set()
    findings = []
    seen = set()
    for ln, line in enumerate(text.splitlines(), 1):
        if len(line) > max_line:
            line = line[:max_line]
        low = line.lower()  # cheap prefilter substrate (see Rule.anchors)
        for rule in rules:
            if rule.anchors and not any(a in low for a in rule.anchors):
                continue
            for m in rule.regex.finditer(line):
                term = m.group(0)
                if term in allow:
                    continue
                key = (ln, rule.id, m.start())
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule_id=rule.id, severity=rule.severity, path=path,
                    line=ln, column=m.start() + 1, match=term,
                    message=rule.message, suggestion=rule.suggestion))
    return findings


def severity_at_least(sev, threshold):
    return SEVERITY_ORDER.get(sev, 1) >= SEVERITY_ORDER.get(threshold, 0)
