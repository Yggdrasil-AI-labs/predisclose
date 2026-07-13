"""Keyword-proximity detection (opt-in). Stdlib only.

Some real secrets have NO distinctive prefix; they are bare hex/alnum/UUID tokens
(Datadog, Algolia, Cloudflare, Heroku, JFrog, ...). A naked regex for "32 hex chars"
would false-positive on every hash. The technique mature scanners (gitleaks,
detect-secrets) use is **keyword proximity**: only flag the token when a provider
keyword sits nearby. This module mirrors that. OFF by default; enable with
`--proximity`.

Rule shape: (rule_id, [keywords], token_regex, severity, message).
Match model: the token shape is matched standalone (not glued to adjacent
alphanumerics) and fires when a provider keyword occurs within WINDOW chars on
EITHER side of it, newlines allowed. Bidirectional + multi-line catches
`token  # datadog` and keyword-on-the-previous-line placements that a
keyword-first same-line model misses. The keyword search excludes the token span
itself, so an alnum token that happens to contain a provider word cannot
self-trigger. Table sourced from gitleaks config/gitleaks.toml @ 09242ce.
"""
import re

from .engine import Finding, SEVERITY_ORDER

WINDOW = 60  # max chars between the provider keyword and the token, either side

# (rule_id, keywords, token-shape regex (secret portion only), severity, message)
KEYWORD_RULES = [
    ("datadog-api-key", ["datadog"], r"[a-f0-9]{32}", "high",
     "Datadog API key near 'datadog'"),
    ("datadog-app-key", ["datadog"], r"[a-f0-9]{40}", "high",
     "Datadog app key near 'datadog'"),
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
    ("jfrog-reference-token", ["jfrog", "artifactory", "bintray", "xray"],
     r"cmVmdGtu[A-Za-z0-9+/=_\-]{16,}", "high", "JFrog reference token near provider keyword"),
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


def _compiled():
    global _COMPILED
    if _COMPILED is None:
        rules = []
        for rid, kws, tok, sev, msg in KEYWORD_RULES:
            kw_rx = re.compile(
                r"(?i)(?:%s)" % "|".join(re.escape(k) for k in kws))
            tok_rx = re.compile(
                r"(?i)(?<![A-Za-z0-9])(%s)(?![A-Za-z0-9])" % tok)
            rules.append((rid, kws, kw_rx, tok_rx,
                          sev if sev in SEVERITY_ORDER else "medium", msg))
        _COMPILED = rules
    return _COMPILED


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
    # a GENERIC assignment hit must not displace a specific provider finding;
    # only specific pattern rules suppress the proximity report for a span
    spans = _covered_spans([f for f in (rule_findings or [])
                            if f.rule_id != "generic-assignment-secret"])
    lowered = text.lower()
    out, seen = [], set()
    for rid, kws, kw_rx, tok_rx, sev, msg in _compiled():
        # cheap gate: never run the token regex unless a keyword is in the file
        if not any(k in lowered for k in kws):
            continue
        for m in tok_rx.finditer(text):
            tok = m.group(1)
            if tok in allow:
                continue
            s, e = m.start(1), m.end(1)
            # keyword within `window` chars before or after the token (newlines ok);
            # the token span itself is excluded so it cannot self-trigger
            if not (kw_rx.search(text, max(0, s - window), s)
                    or kw_rx.search(text, e, e + window)):
                continue
            line, col = _linecol(text, s)
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
