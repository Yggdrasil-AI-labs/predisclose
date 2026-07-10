"""leakguard agent: an autonomous triage loop over the scan engine.

LeakGuard's job is unchanged - catch secrets, PII, and internal identifiers
before they go public. This module runs that job as an AGENT rather than a
one-shot scan: it scans, asks a LOCAL model to judge each finding (real leak vs
false positive vs intentionally-public), acts on the judgment (proposes or
applies allowlist entries, surfaces the real leaks with a fix), then re-scans -
looping until the artifact is clean or a step budget is hit.

Design:
  - Control flow lives here in Python and is BOUNDED (max_steps). The model
    provides per-finding JUDGMENT only, never control flow, so it stays
    model-agnostic and works with small local models that do not do native
    tool-calling.
  - Local-first: transport, config, and JSON parsing are reused from
    leakguard.ai (stdlib urllib; the default endpoint is a localhost model).
  - Conservative: any finding the model cannot classify (endpoint down,
    unparseable reply) stays a real_leak. The agent never hides a possible leak.
  - Detection / proposal-only: like the rest of leakguard it NEVER edits your
    scanned content. With apply_allow it may append entries to your PRIVATE
    rules file (.leakguard.local.json) - that is configuration, not content, and
    that file is gitignored.
"""
import json
import os

from . import ai
from .engine import LOCAL_RULES_NAME

VERDICTS = ("real_leak", "false_positive", "allowlist_candidate")

_TRIAGE_SYSTEM = (
    "You are the triage step of leakguard, a scanner that catches secrets, PII, "
    "and internal identifiers before they are published to a PUBLIC place. You "
    "are given ONE finding and the lines around it. Classify it as exactly one "
    "of:\n"
    "- real_leak: genuinely sensitive; must be removed, rotated, or redacted "
    "before publishing.\n"
    "- false_positive: the pattern matched but this is not sensitive - a test "
    "fixture, an obvious placeholder (the AWS docs example key, a value like "
    "changeme'), a documentation example, an RFC5737 IP (203.0.113.x), an "
    "example.com address.\n"
    "- allowlist_candidate: a real, correct match that is nonetheless MEANT to "
    "be public - a public handle, a published support address, an intentionally "
    "shared value.\n"
    "Be conservative: when unsure, choose real_leak. Respond with ONLY a JSON "
    'object: {"verdict": "real_leak|false_positive|allowlist_candidate", '
    '"confidence": <number 0..1>, "reason": "<one sentence>", '
    '"action": "<what to do before publishing>"}.'
)


def _context(text, line, radius=3):
    """Return the finding's line plus `radius` lines on each side, numbered."""
    lines = text.splitlines()
    lo = max(1, line - radius)
    hi = min(len(lines), line + radius)
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(lo, hi + 1))


def _chat(cfg, system, user_obj):
    """One local-model call returning a parsed JSON object, or None on any
    transport/parse error. Uses the same stdlib transport as the --review layer,
    so ai._http_post_json is the single mock point in tests."""
    payload = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_obj)},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    headers = {"Content-Type": "application/json", "User-Agent": "leakguard"}
    if cfg.get("key"):
        headers["Authorization"] = f"Bearer {cfg['key']}"
    try:
        resp = ai._http_post_json(cfg["base"] + "/chat/completions", payload,
                                  headers, cfg["timeout"])
        content = resp["choices"][0]["message"]["content"]
    except Exception:
        return None
    return ai._extract_json_object(content)


def triage_finding(finding, file_text, cfg):
    """Judge a single finding. Returns a dict with verdict/confidence/reason/
    action. Falls back to a conservative real_leak verdict when the model is
    unavailable or replies with something unusable."""
    user = {
        "path": finding.path,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "matched_text": finding.match,
        "engine_message": finding.message,
        "line": finding.line,
        "context": _context(file_text, finding.line),
    }
    obj = _chat(cfg, _TRIAGE_SYSTEM, user)
    verdict = obj.get("verdict") if isinstance(obj, dict) else None
    if verdict not in VERDICTS:
        return {"verdict": "real_leak", "confidence": 0.0,
                "reason": "untriaged (model unavailable or unclear reply)",
                "action": finding.suggestion or "review before publishing"}
    conf = obj.get("confidence")
    try:
        conf = max(0.0, min(1.0, float(conf)))
    except (TypeError, ValueError):
        conf = 0.0
    return {
        "verdict": verdict,
        "confidence": conf,
        "reason": str(obj.get("reason", "")).strip(),
        "action": str(obj.get("action", "") or finding.suggestion).strip(),
    }


def _apply_allow_entries(terms, local_rules_path):
    """Append literal `terms` to the "allow" list of the private rules file,
    creating a minimal one if it does not exist. Returns the terms actually
    written. This touches CONFIG (gitignored), never scanned content."""
    data = {"rules": [], "allow": []}
    if os.path.isfile(local_rules_path):
        try:
            with open(local_rules_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            return []
    existing = data.get("allow")
    if not isinstance(existing, list):
        existing = []
    added = [t for t in terms if t not in existing]
    if not added:
        return []
    data["allow"] = existing + added
    try:
        with open(local_rules_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
    except OSError:
        return []
    return added


def run_agent(paths, rules, allow, root=".", cfg=None, max_steps=3,
              apply_allow=False, local_rules_path=None, scanner=None,
              reader=None):
    """Run the scan -> triage -> act -> re-scan loop.

    `scanner(paths, rules, allow, root) -> (findings, files_scanned)` and
    `reader(path) -> str` are injectable for tests; they default to the real
    filesystem scan and a capped UTF-8 read.

    Returns a result dict:
      steps, files_scanned, clean (bool), triaged (list of {finding, verdict}),
      real_leaks (list[Finding]), false_positives (list[Finding]),
      proposed_allow (list[str]), applied_allow (list[str]).
    """
    if scanner is None:
        from .fsscan import scan_paths
        scanner = lambda p, r, a, rt: scan_paths(p, r, a, root=rt)
    if reader is None:
        reader = _read_text
    cfg = cfg or ai.llm_config_from_env()
    allow = set(allow or ())
    if local_rules_path is None:
        local_rules_path = os.path.join(root, LOCAL_RULES_NAME)

    triaged = []
    proposed, applied = [], []
    files_scanned = 0
    clean = False
    step = 0
    while step < max_steps:
        step += 1
        findings, files_scanned = scanner(paths, rules, allow, root)
        if not findings:
            clean = True
            break
        texts = {}
        triaged = []
        for f in findings:
            if f.path not in texts:
                texts[f.path] = reader(f.path)
            triaged.append({"finding": f,
                            "verdict": triage_finding(f, texts[f.path], cfg)})
        candidates = sorted({t["finding"].match for t in triaged
                             if t["verdict"]["verdict"] == "allowlist_candidate"
                             and t["finding"].match not in allow})
        if apply_allow and candidates:
            written = _apply_allow_entries(candidates, local_rules_path)
            if written:
                allow.update(written)
                applied.extend(written)
                continue  # re-scan with the expanded allowlist
        proposed = candidates
        break

    real_leaks = [t["finding"] for t in triaged
                  if t["verdict"]["verdict"] == "real_leak"]
    false_positives = [t["finding"] for t in triaged
                       if t["verdict"]["verdict"] == "false_positive"]
    return {
        "steps": step,
        "files_scanned": files_scanned,
        "clean": clean,
        "triaged": triaged,
        "real_leaks": real_leaks,
        "false_positives": false_positives,
        "proposed_allow": proposed,
        "applied_allow": applied,
    }


def _read_text(path, max_bytes=1_000_000):
    try:
        with open(path, "rb") as fh:
            return fh.read(max_bytes).decode("utf-8", "replace")
    except OSError:
        return ""
