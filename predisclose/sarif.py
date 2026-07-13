"""SARIF 2.1.0 output. Lets GitHub code scanning ingest findings via the
github/codeql-action/upload-sarif action, so leaks surface in the Security tab.
Stdlib only.

Matched values are REDACTED in the SARIF (it gets uploaded and rendered): the
report shows where a secret is, not the secret itself.
"""
from . import __version__

_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
          "Schemata/sarif-schema-2.1.0.json")
INFO_URI = "https://github.com/Yggdrasil-AI-labs/predisclose"


def redact(s):
    """Mask a matched value so the secret is never written into the SARIF."""
    if not s:
        return ""
    if len(s) <= 6:
        return s[0] + "***"
    return s[:4] + "***" + s[-2:]


def _rule_objects(findings):
    rules, index = [], {}
    for f in findings:
        if f.rule_id in index:
            continue
        index[f.rule_id] = len(rules)
        rules.append({
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.message or f.rule_id},
            "fullDescription": {"text": f.message or f.rule_id},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            "helpUri": INFO_URI,
            "properties": {"severity": f.severity},
        })
    return rules, index


def _result(f, index):
    red = redact(f.match)
    msg = f.message or f.rule_id
    if f.suggestion:
        msg += " -- " + f.suggestion
    if getattr(f, "commit", ""):
        msg += " (seen in commit %s)" % f.commit
    result = {
        "ruleId": f.rule_id,
        "ruleIndex": index[f.rule_id],
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": "%s: %s" % (msg, red)},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.path},
                "region": {
                    "startLine": max(int(f.line), 1),
                    "startColumn": max(int(f.column), 1),
                    "endColumn": max(int(f.column), 1) + len(f.match),
                    "snippet": {"text": red},
                },
            }
        }],
        "partialFingerprints": {
            "predisclose/v1": "%s:%s:%s:%s" % (f.rule_id, f.path, f.line, red)
        },
    }
    props = {}
    if getattr(f, "commit", ""):
        props["commit"] = f.commit
    if getattr(f, "verified", ""):
        props["verified"] = f.verified
    if props:
        result["properties"] = props
    return result


def build_sarif(findings, tool_version=__version__):
    rules, index = _rule_objects(findings)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "predisclose",
                "informationUri": INFO_URI,
                "version": tool_version,
                "rules": rules,
            }},
            "results": [_result(f, index) for f in findings],
        }],
    }
