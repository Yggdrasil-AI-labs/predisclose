"""High-entropy string detection (opt-in). Stdlib only.

Pattern rules catch known secret SHAPES. Entropy detection is the complementary
net: it flags long, high-Shannon-entropy base64/hex-ish tokens that look random
enough to be a credential even when no specific pattern matched. It is OFF by
default (noisy by nature). Enable it with `--entropy` on the CLI or an "entropy"
block in your private rules file:

  {"entropy": {"enabled": true, "b64_threshold": 4.2, "severity": "low"}}

Noise control:
  * Tokens must clear BOTH a length and a Shannon-entropy threshold.
  * Findings default to LOW severity, so they never block a commit unless the
    user opts in with --fail-on low.
  * The `allow` list is honored (same literal-match semantics as pattern rules).
  * Tokens already covered by a pattern match on the same line are skipped, so a
    flagged AWS key is not also reported as a high-entropy string.
  * Obvious false positives are skipped: known lockfiles, subresource-integrity
    hashes (sha256-/sha512-), and 40-char git object hashes.
"""
import json
import math
import os
import re

from .engine import Finding, SEVERITY_ORDER

RULE_ID = "high-entropy-string"

# Candidate token shapes. Final length/entropy gating is done against the options.
_B64_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")

# Files whose contents are mostly generated hashes -> skip entirely.
_LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "poetry.lock", "pipfile.lock", "cargo.lock", "composer.lock", "go.sum",
    "gemfile.lock", "packages.lock.json", "flake.lock",
}
# Token prefixes that mark a benign subresource-integrity / package hash.
_INTEGRITY_PREFIXES = ("sha1-", "sha256-", "sha384-", "sha512-")


class EntropyOptions:
    __slots__ = ("enabled", "min_b64_len", "b64_threshold",
                 "min_hex_len", "hex_threshold", "severity")

    def __init__(self, enabled=False, min_b64_len=20, b64_threshold=4.0,
                 min_hex_len=32, hex_threshold=3.0, severity="low"):
        self.enabled = enabled
        self.min_b64_len = min_b64_len
        self.b64_threshold = b64_threshold
        self.min_hex_len = min_hex_len
        self.hex_threshold = hex_threshold
        self.severity = severity if severity in SEVERITY_ORDER else "low"


def shannon_entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def is_lockfile(path):
    return os.path.basename(path).lower() in _LOCKFILE_NAMES


def _looks_benign(token):
    low = token.lower()
    if low.startswith(_INTEGRITY_PREFIXES):
        return True
    # 40-char git object hashes are everywhere and almost never secrets.
    if re.fullmatch(r"[0-9a-f]{40}", low):
        return True
    return False


def _spans_from_findings(findings):
    spans = {}
    for f in findings:
        spans.setdefault(f.line, []).append((f.column - 1, f.column - 1 + len(f.match)))
    return spans


def _overlaps(spans, line, start, end):
    for (s, e) in spans.get(line, ()):
        if start < e and s < end:
            return True
    return False


def entropy_findings(text, allow, path, opts, rule_findings=None, max_line=200_000):
    """Return high-entropy Findings for `text`. No-op unless opts.enabled."""
    if not opts or not opts.enabled:
        return []
    if is_lockfile(path):
        return []
    allow = allow or set()
    spans = _spans_from_findings(rule_findings or [])
    out = []
    seen = set()
    for ln, line in enumerate(text.splitlines(), 1):
        if len(line) > max_line:
            line = line[:max_line]
        for rx, min_len, thr in (
            (_B64_RE, opts.min_b64_len, opts.b64_threshold),
            (_HEX_RE, opts.min_hex_len, opts.hex_threshold),
        ):
            for m in rx.finditer(line):
                tok = m.group(0)
                if len(tok) < min_len:
                    continue
                if tok in allow or _looks_benign(tok):
                    continue
                if shannon_entropy(tok) < thr:
                    continue
                start = m.start()
                key = (ln, start, tok)
                if key in seen:
                    continue
                if _overlaps(spans, ln, start, start + len(tok)):
                    continue
                seen.add(key)
                out.append(Finding(
                    rule_id=RULE_ID, severity=opts.severity, path=path,
                    line=ln, column=start + 1, match=tok,
                    message="high-entropy string (possible secret)",
                    suggestion="confirm it is not a credential; if it is, rotate and remove it"))
    return out


def _read_entropy_config(extra_paths, scan_root):
    """Merge any "entropy" objects from the same JSON files the engine reads."""
    merged = {}
    paths = list(extra_paths or [])
    env_path = os.environ.get("LEAKGUARD_RULES")
    if env_path:
        paths.append(env_path)
    paths.append(os.path.join(scan_root or ".", ".leakguard.local.json"))
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("entropy"), dict):
            merged.update(data["entropy"])
    return merged


def load_entropy_options(cli_enabled=False, cli_threshold=None,
                         extra_paths=None, scan_root="."):
    """Build EntropyOptions from config file(s) then apply CLI overrides."""
    opts = EntropyOptions()
    cfg = _read_entropy_config(extra_paths, scan_root)
    if cfg:
        opts.enabled = bool(cfg.get("enabled", opts.enabled))
        try:
            opts.min_b64_len = int(cfg.get("min_b64_len", opts.min_b64_len))
            opts.b64_threshold = float(cfg.get("b64_threshold", opts.b64_threshold))
            opts.min_hex_len = int(cfg.get("min_hex_len", opts.min_hex_len))
            opts.hex_threshold = float(cfg.get("hex_threshold", opts.hex_threshold))
        except (TypeError, ValueError):
            pass
        sev = cfg.get("severity", opts.severity)
        if sev in SEVERITY_ORDER:
            opts.severity = sev
    if cli_enabled:
        opts.enabled = True
    if cli_threshold is not None:
        opts.b64_threshold = float(cli_threshold)
    return opts
