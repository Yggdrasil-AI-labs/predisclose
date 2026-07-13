"""Baseline support: adopt predisclose into a repo that already has findings.

A baseline records a fingerprint of each current finding. On later scans, any
finding whose fingerprint is in the baseline is suppressed, so only NEW leaks are
reported (and gate CI). Rotating or changing a secret changes its fingerprint, so
it resurfaces. The baseline stores only hashes of matches, never the secrets, so
it is safe to commit. Stdlib only.
"""
import hashlib
import json

from . import __version__

BASELINE_VERSION = 1


def fingerprint(finding):
    """Stable per-finding id, independent of line number. Hashes the match so the
    baseline file never stores the secret itself."""
    h = hashlib.sha256()
    for part in (finding.rule_id, finding.path, finding.match):
        h.update(part.encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()[:16]


def load_baseline(path):
    """Return (set_of_fingerprints, error_or_None). Missing file -> empty set."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return set(), None
    except (OSError, ValueError) as e:
        return set(), str(e)
    fps = data.get("fingerprints", []) if isinstance(data, dict) else data
    return set(fps or []), None


def write_baseline(path, findings):
    """Write a baseline covering all `findings`. Returns the count written."""
    fps = sorted({fingerprint(f) for f in findings})
    doc = {
        "predisclose_baseline_version": BASELINE_VERSION,
        "generated_by": f"predisclose {__version__}",
        "fingerprints": fps,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return len(fps)


def filter_new(findings, baseline_set):
    """Drop findings already present in the baseline."""
    return [f for f in findings if fingerprint(f) not in baseline_set]
