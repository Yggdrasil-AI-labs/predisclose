"""Keyword-proximity detection (opt-in). Stdlib only.

Some real secrets have NO distinctive prefix — they are bare hex/alnum/UUID tokens
(Datadog, Algolia, Cloudflare, Heroku, JFrog, ...). A naked regex for "32 hex chars"
would false-positive on every hash. The technique mature scanners (gitleaks,
detect-secrets) use is **keyword proximity**: only flag the token when a provider
keyword sits nearby. This module mirrors that — keyword-first, same line, within a
small window. OFF by default; enable with `--proximity`.

Rule shape: (rule_id, [keywords], token_regex, severity, message).
Match model: (?i) <keyword> [^newline]{0,WINDOW}? (token)   with token not glued to
adjacent alphanumerics. Table sourced from gitleaks config/gitleaks.toml @ 09242ce.
"""
import re

from .engine import Finding, SEVERITY_ORDER

WINDOW = 30  # max chars between the provider keyword and the token, same line

# (rule_id, keywords, token-shape regex (secret portion only), severity, message)
KEYWORD_RULES = [
    ("datadog-access-token", ["datadog"], r"[a-z0-9]{40}", "medium",
     "Datadog access token near 'datadog'"),
    ("algolia-api-key", ["algolia"], r"[a-z0-9]{32}", "medium",
     "Algolia API/admin key near 'algolia'"),
    ("cloudflare-global-api-key", ["cloudflare"], r"[a-f0-9]{37}", "high",
     "Cloudflare global API key near 'cloudflare'"),
    ("cloudflare-api-token", ["cloudflare"], r"[a-z0-9_-]{40}", "high",
     "Cloudflare API token near 'cloudflare'"),
    ("heroku-api-key", ["heroku"],
     r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high",
     "Heroku API key (UUID) near 'heroku'"),
    ("jfrog-api-key", ["jfrog", "artifactory", "bintray", "xray"], r"[a-z0-9]{73}",
     "high", "JFrog/Artifactory API key near provider keyword"),
    ("jfrog-identity-token", ["jfrog", "artifactory", "bintray", "xray"], r"[a-z0-9]{64}",
     "high", "JFrog identity token near provider keyword"),
    ("facebook-app-secret", ["facebook"], r"[a-f0-9]{32}", "high",
     "Facebook app secret near 'facebook'"),
    ("mapbox-token", ["mapbox"], r"pk\.[a-z0-9]{60}\.[a-z0-9]{22}", "medium",
     "Mapbox token near 'mapbox'"),
    ("twitter-api-secret", ["twitter"], r"[a-z0-9]{50}", "medium",
     "Twitter/X API secret near 'twitter'"),
    ("twitter-access-secret", ["twitter"], r"[a-z0-9]{45}", "medium",
     "Twitter/X access secret near 'twitter'"),
]

_COMPILED = None


def _compiled(window=WINDOW):
    global _COMPILED
    if _COMPILED is None or _COMPILED[0] != window:
        rules = []
        for rid, kws, tok, sev, msg in KEYWORD_RULES:
            kw = "|".join(re.escape(k) for k in kws)
            rx = re.compile(
                r"(?i)(?:%s)[^\n]{0,%d}?(?<![A-Za-z0-9])(%s)(?![A-Za-z0-9])"
                % (kw, window, tok))
            rules.append((rid, rx, sev if sev in SEVERITY_ORDER else "medium", msg))
        _COMPILED = (window, rules)
    return _COMPILED[1]


def _linecol(text, pos):
    line = text.count("\n", 0, pos) + 1
    col = pos - (text.rfind("\n", 0, pos) + 1) + 1
    return line, col


def _covered_spans(rule_findings):
    spans = {}
    for f in rule_findings or []:
        spans.setdefault(f.line, []).append((f.column - 1, f.column - 1 + len(f.match)))
    return spans


def proximity_findings(text, allow=None, path="<text>", rule_findings=None, window=WINDOW):
    """Keyword-proximity findings. No-op unless called (the CLI gates on --proximity)."""
    allow = allow or set()
    spans = _covered_spans(rule_findings)
    out, seen = [], set()
    for rid, rx, sev, msg in _compiled(window):
        for m in rx.finditer(text):
            tok = m.group(1)
            if tok in allow:
                continue
            pos = m.start(1)
            line, col = _linecol(text, pos)
            # skip if a pattern rule already flagged this span (no double-report)
            if any(c0 < (col - 1 + len(tok)) and (col - 1) < c1
                   for (c0, c1) in spans.get(line, ())):
                continue
            key = (rid, line, col, tok)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                rule_id=rid, severity=sev, path=path, line=line, column=col,
                match=tok, message=msg,
                suggestion="confirm and rotate; flagged by a nearby provider keyword"))
    return out
