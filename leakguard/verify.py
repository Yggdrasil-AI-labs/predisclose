"""Opt-in live verification for a handful of high-value credential types.

Stdlib `urllib` only; OFF by default. With `--verify`, leakguard asks the provider
whether each supported credential is currently valid:

  active   -> the provider accepted it; it works right now (rotate immediately)
  inactive -> the provider rejected it (401); likely already revoked/expired
  unknown  -> network error, rate limit, or an ambiguous status; could not tell

Unsupported finding types are left unverified (""). Network calls happen ONLY for
supported types and ONLY when --verify is passed. Never raises.

This intentionally covers a small, high-signal set rather than chasing every
provider; it answers "is this leaked credential live?" without pretending to be
a full verification engine. AWS/GCP (request signing) are deferred.
"""
import base64
import json
import urllib.error
import urllib.request

TIMEOUT = 10
_UA = {"User-Agent": "leakguard"}


def _status(url, headers, method="GET", data=None, ok_json=None, timeout=TIMEOUT):
    try:
        req = urllib.request.Request(url, headers=headers, method=method, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = getattr(r, "status", r.getcode())
            body = r.read().decode("utf-8", "replace")
        if code == 200:
            if ok_json is None:
                return "active"
            try:
                return "active" if ok_json(json.loads(body)) else "inactive"
            except ValueError:
                return "unknown"
        return "unknown"
    except urllib.error.HTTPError as e:
        return "inactive" if e.code == 401 else "unknown"
    except Exception:
        return "unknown"


def _github(t):
    return _status("https://api.github.com/user", dict(_UA, Authorization=f"Bearer {t}"))


def _gitlab(t):
    return _status("https://gitlab.com/api/v4/user", dict(_UA, **{"PRIVATE-TOKEN": t}))


def _slack(t):
    return _status("https://slack.com/api/auth.test", dict(_UA, Authorization=f"Bearer {t}"),
                   method="POST", ok_json=lambda j: j.get("ok") is True)


def _stripe(t):
    cred = base64.b64encode((t + ":").encode()).decode()
    return _status("https://api.stripe.com/v1/account", dict(_UA, Authorization=f"Basic {cred}"))


def _sendgrid(t):
    return _status("https://api.sendgrid.com/v3/scopes", dict(_UA, Authorization=f"Bearer {t}"))


def _npm(t):
    return _status("https://registry.npmjs.org/-/whoami", dict(_UA, Authorization=f"Bearer {t}"))


def _openai(t):
    return _status("https://api.openai.com/v1/models", dict(_UA, Authorization=f"Bearer {t}"))


def _anthropic(t):
    return _status("https://api.anthropic.com/v1/models",
                   dict(_UA, **{"x-api-key": t, "anthropic-version": "2023-06-01"}))


def _huggingface(t):
    return _status("https://huggingface.co/api/whoami-v2", dict(_UA, Authorization=f"Bearer {t}"))


VERIFIERS = {
    "github-token": _github,
    "github-pat-fine-grained": _github,
    "gitlab-pat": _gitlab,
    "slack-token": _slack,
    "stripe-secret-key": _stripe,
    "sendgrid-api-key": _sendgrid,
    "npm-access-token": _npm,
    "openai-api-key": _openai,
    "anthropic-api-key": _anthropic,
    "huggingface-token": _huggingface,
}


def supported():
    return set(VERIFIERS)


def verify_findings(findings, timeout=TIMEOUT):
    """Annotate each supported finding's `.verified` in place. Dedupes identical
    (rule_id, match) so a secret repeated across files costs one API call.
    Returns a counts dict {active, inactive, unknown}."""
    cache = {}
    counts = {"active": 0, "inactive": 0, "unknown": 0}
    for f in findings:
        fn = VERIFIERS.get(f.rule_id)
        if fn is None:
            continue
        key = (f.rule_id, f.match)
        if key not in cache:
            try:
                cache[key] = fn(f.match)
            except Exception:
                cache[key] = "unknown"
        f.verified = cache[key]
        counts[f.verified] = counts.get(f.verified, 0) + 1
    return counts
