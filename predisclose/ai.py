"""Optional AI detection layers for predisclose (the ``predisclose[ai]`` extra).

These are LOCAL, opt-in supplements to the regex engine. They emit the same
``Finding`` objects and flow through the same exit-code path, so ``--presidio``
and ``--review`` simply add findings to whatever the built-in / private rules
already caught.

Layer 1 - Presidio:
    Microsoft ``presidio-analyzer`` (with a spaCy model) as a second PII
    detector. Each ``RecognizerResult`` becomes a ``Finding``; entity types map
    to severities and the engine's ``allow`` list is honored. Presidio is
    lazy-imported - if the extra is not installed, predisclose prints a one-line
    install hint and skips the layer. The zero-dependency core never breaks.

Layer 2 - Local-LLM review:
    Sends the scanned text plus the findings collected so far to a LOCAL
    OpenAI-compatible ``/v1/chat/completions`` endpoint and asks the model to
    flag MISSES - secrets / PII / internal identifiers the rules and Presidio
    did not catch. Uses stdlib ``urllib`` only (no client library). It is
    model-agnostic and local-first: the default endpoint is a localhost server
    (Ollama's default port); pointing it anywhere remote is strictly opt-in via
    env vars.

Environment (all optional):
    PREDISCLOSE_LLM_BASE            OpenAI-compatible base URL
                                  (default ``http://localhost:11434/v1``)
    PREDISCLOSE_LLM_MODEL           model name (default ``llama3.1``)
    PREDISCLOSE_LLM_KEY             bearer token, only for endpoints that need auth
    PREDISCLOSE_LLM_TIMEOUT         per-request timeout, seconds (default ``60``)
    PREDISCLOSE_LLM_MAX_CHARS       max chars of a file sent for review (default ``16000``)
    PREDISCLOSE_PRESIDIO_THRESHOLD  drop Presidio hits below this score (default ``0.5``)
    PREDISCLOSE_PRESIDIO_LANG       spaCy language (default ``en``)

No organization-specific values live here. Your real endpoint, model, and any
custom Presidio recognizers belong in your private env/config, not this repo.
"""
import json
import os
import sys
import urllib.request

from .engine import Finding, SEVERITY_ORDER


def _note(msg):
    print(f"predisclose: {msg}", file=sys.stderr)


# ---- Presidio (layer 1) ----------------------------------------------------

# Presidio entity type -> predisclose severity. Unknown entities default to medium.
PRESIDIO_SEVERITY = {
    "CREDIT_CARD": "high",
    "CRYPTO": "high",
    "IBAN_CODE": "high",
    "US_SSN": "high",
    "US_ITIN": "high",
    "US_BANK_NUMBER": "high",
    "US_PASSPORT": "high",
    "US_DRIVER_LICENSE": "high",
    "MEDICAL_LICENSE": "high",
    "PHONE_NUMBER": "medium",
    "IP_ADDRESS": "medium",
    "PERSON": "medium",
    "NRP": "medium",
    "EMAIL_ADDRESS": "low",
    "LOCATION": "low",
    "URL": "low",
    "DATE_TIME": "low",
}
DEFAULT_PRESIDIO_SEVERITY = "medium"

_ANALYZER = None
_ANALYZER_TRIED = False
_PRESIDIO_HINTED = False


def _get_analyzer():
    """Return a cached presidio AnalyzerEngine, or None if presidio is missing.

    Tests can bypass the heavy import/init by setting ``predisclose.ai._ANALYZER``.
    """
    global _ANALYZER, _ANALYZER_TRIED
    if _ANALYZER is not None:
        return _ANALYZER
    if _ANALYZER_TRIED:
        return None
    _ANALYZER_TRIED = True
    try:
        from presidio_analyzer import AnalyzerEngine
    except Exception:
        return None
    try:
        _ANALYZER = AnalyzerEngine()
    except Exception as e:  # spaCy model missing, etc.
        _note(f"presidio failed to initialize ({e}); skipping --presidio")
        return None
    return _ANALYZER


def _line_col(text, offset):
    """1-based (line, column) for a character offset into text."""
    nl = text.count("\n", 0, offset)
    line_start = text.rfind("\n", 0, offset) + 1
    return nl + 1, offset - line_start + 1


def presidio_scan(text, allow=None, path="<text>"):
    """Run Presidio over text and return Findings. Never raises; skips with a
    one-time install hint if the presidio extra is not installed."""
    global _PRESIDIO_HINTED
    allow = allow or set()
    analyzer = _get_analyzer()
    if analyzer is None:
        if not _PRESIDIO_HINTED:
            _PRESIDIO_HINTED = True
            _note("--presidio needs the AI extra: pip install 'predisclose[ai]' "
                  "plus a spaCy model (python -m spacy download en_core_web_lg)")
        return []
    lang = os.environ.get("PREDISCLOSE_PRESIDIO_LANG", "en")
    try:
        threshold = float(os.environ.get("PREDISCLOSE_PRESIDIO_THRESHOLD", "0.5"))
    except ValueError:
        threshold = 0.5
    try:
        results = analyzer.analyze(text=text, language=lang)
    except Exception as e:
        _note(f"presidio analyze error on {path}: {e}")
        return []
    findings = []
    for r in results or []:
        score = getattr(r, "score", 1.0) or 0.0
        if score < threshold:
            continue
        term = text[r.start:r.end]
        if term in allow:
            continue
        line, col = _line_col(text, r.start)
        sev = PRESIDIO_SEVERITY.get(r.entity_type, DEFAULT_PRESIDIO_SEVERITY)
        findings.append(Finding(
            rule_id=f"presidio:{r.entity_type}", severity=sev, path=path,
            line=line, column=col, match=term,
            message=f"Presidio PII: {r.entity_type} (score {score:.2f})",
            suggestion="confirm this PII is intended for public release, or redact"))
    return findings


# ---- Local-LLM review (layer 2) --------------------------------------------

DEFAULT_LLM_BASE = "http://localhost:11434/v1"
DEFAULT_LLM_MODEL = "llama3.1"

_LLM_ERROR_HINTED = False

_REVIEW_SYSTEM = (
    "You are a disclosure reviewer for an open-source secret/PII scanner. "
    "You are given the text of one file and the list of findings a regex engine "
    "and Presidio already produced. Flag ADDITIONAL leaks those layers MISSED: "
    "secrets, credentials, API keys, private hostnames or IP addresses, personal "
    "data, or other clearly sensitive disclosures. Do not repeat findings that "
    "are already listed. Be conservative - only report things you are confident "
    "are real leaks. Respond with ONLY a JSON object of the form "
    '{"findings": [{"line": <int>, "severity": "low|medium|high", '
    '"match": "<the exact leaked substring>", "message": "<why it is sensitive>", '
    '"suggestion": "<how to fix>"}]}. If nothing was missed, return '
    '{"findings": []}.'
)


def llm_config_from_env():
    base = os.environ.get("PREDISCLOSE_LLM_BASE", DEFAULT_LLM_BASE).rstrip("/")
    try:
        timeout = float(os.environ.get("PREDISCLOSE_LLM_TIMEOUT", "60"))
    except ValueError:
        timeout = 60.0
    try:
        max_chars = int(os.environ.get("PREDISCLOSE_LLM_MAX_CHARS", "16000"))
    except ValueError:
        max_chars = 16000
    return {
        "base": base,
        "model": os.environ.get("PREDISCLOSE_LLM_MODEL", DEFAULT_LLM_MODEL),
        "key": os.environ.get("PREDISCLOSE_LLM_KEY", ""),
        "timeout": timeout,
        "max_chars": max_chars,
    }


def _http_post_json(url, payload, headers, timeout):
    """POST JSON and return the parsed JSON response. Stdlib only; tests mock it."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _extract_json_object(s):
    """Parse s as JSON; tolerate code fences and surrounding prose by pulling the
    first balanced ``{...}`` block out. Returns a dict/list or None."""
    s = (s or "").strip()
    if s.startswith("```"):
        s = s.strip("`")
        nl = s.find("\n")
        if nl != -1 and s[:nl].strip().lower() in ("json", ""):
            s = s[nl + 1:]
    try:
        return json.loads(s)
    except Exception:
        pass
    start = s.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i + 1])
                except Exception:
                    return None
    return None


def _findings_summary(findings, limit=50):
    return [{"line": f.line, "rule": f.rule_id, "match": f.match}
            for f in findings[:limit]]


def _find_line(lines, term):
    for i, ln in enumerate(lines, 1):
        if term in ln:
            return i
    return 1


def llm_review_scan(text, prior_findings, path="<text>", allow=None, cfg=None):
    """Ask a local OpenAI-compatible model to flag leaks the other layers missed.
    Never raises; on any transport/parse error it prints a note once and skips."""
    global _LLM_ERROR_HINTED
    allow = allow or set()
    cfg = cfg or llm_config_from_env()
    snippet = text[:cfg["max_chars"]]
    user = {
        "path": path,
        "truncated": len(text) > cfg["max_chars"],
        "already_found": _findings_summary(prior_findings),
        "file_text": snippet,
    }
    payload = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": _REVIEW_SYSTEM},
            {"role": "user", "content": json.dumps(user)},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    headers = {"Content-Type": "application/json", "User-Agent": "predisclose"}
    if cfg["key"]:
        headers["Authorization"] = f"Bearer {cfg['key']}"
    url = cfg["base"] + "/chat/completions"
    try:
        resp = _http_post_json(url, payload, headers, cfg["timeout"])
    except Exception as e:
        if not _LLM_ERROR_HINTED:
            _LLM_ERROR_HINTED = True
            _note(f"--review: LLM endpoint unreachable at {cfg['base']} ({e}); "
                  "set PREDISCLOSE_LLM_BASE / PREDISCLOSE_LLM_MODEL. Skipping review.")
        return []
    return _parse_review(resp, text, path, allow)


def _parse_review(resp, text, path, allow):
    try:
        content = resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return []
    obj = _extract_json_object(content)
    if not isinstance(obj, dict):
        return []
    items = obj.get("findings")
    if not isinstance(items, list):
        return []
    lines = text.splitlines()
    findings = []
    for it in items:
        if not isinstance(it, dict):
            continue
        term = str(it.get("match", "")).strip()
        if not term or term in allow:
            continue
        sev = it.get("severity", "medium")
        if sev not in SEVERITY_ORDER:
            sev = "medium"
        line = it.get("line")
        if not isinstance(line, int) or line < 1 or line > len(lines):
            line = _find_line(lines, term)
        col = 1
        if 1 <= line <= len(lines):
            idx = lines[line - 1].find(term)
            if idx != -1:
                col = idx + 1
        findings.append(Finding(
            rule_id="llm-review", severity=sev, path=path, line=line, column=col,
            match=term, message=str(it.get("message", "LLM-flagged disclosure")),
            suggestion=str(it.get("suggestion", "review and redact if sensitive"))))
    return findings


# ---- shared front-end hook -------------------------------------------------

def make_hook(use_presidio=False, use_review=False, allow=None):
    """Return a per-file callable ``hook(text, path, base_findings) -> [Finding]``
    running the enabled AI layers, or None if neither is enabled. The LLM review
    sees the regex findings plus any Presidio findings so it can target misses."""
    if not (use_presidio or use_review):
        return None
    allow = allow or set()
    cfg = llm_config_from_env() if use_review else None

    def hook(text, path, base_findings):
        extra = []
        if use_presidio:
            extra += presidio_scan(text, allow, path)
        if use_review:
            extra += llm_review_scan(text, list(base_findings) + extra, path,
                                     allow, cfg)
        return extra

    return hook
