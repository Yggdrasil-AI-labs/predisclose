"""predisclose command-line interface.

  predisclose scan [PATH ...]      scan files/dirs (default: .)
  predisclose scan --staged        scan git staged content (pre-commit hook)
  predisclose scan --history       scan the full git history (committed-then-removed)
  predisclose github --org ACME    scan an org's public repos (post-publish audit)
  predisclose agent [PATH ...]     scan -> judge each finding with a LOCAL model ->
                                 act -> re-scan, looping until clean (local LLM)

Add --entropy to any local scan to also flag high-entropy strings no pattern
matched. Output formats: text (default), json, sarif (GitHub code scanning),
md (a Markdown summary for a job summary / PR comment). --notify-webhook posts a
summary to Slack/Discord/a generic webhook when findings hit the threshold.

Optional AI layers (need the `predisclose[ai]` extra; see predisclose/ai.py):
  --presidio   add a Microsoft Presidio PII pass (local)
  --review     ask a LOCAL OpenAI-compatible LLM to flag misses (local-first)

Exit codes: 0 = clean / below threshold, 1 = findings at-or-above --fail-on,
2 = usage/config error. Detection only; predisclose never edits your content.
"""
import argparse
import json
import os
import sys

from . import __version__
from .engine import load_rules, severity_at_least
from .entropy import load_entropy_options
from .fsscan import scan_paths, scan_staged
from .github_scan import scan_github
from .history import scan_history
from .notify import notify, webhook_from_env
from .report import build_markdown, build_summary_text
from .sarif import build_sarif

SEV_COLOR = {"high": "31", "medium": "33", "low": "36"}  # ansi red/yellow/cyan

INIT_TEMPLATE = """{
  "_comment": [
    "Your PRIVATE predisclose rules. This file is gitignored and must NEVER be",
    "committed - it is the inventory of internal identifiers you do not want to",
    "leak. predisclose auto-loads it from the repo root. Replace the placeholders",
    "below with your real internal hostnames, project codenames, people, paths,",
    "etc. Fields: id, pattern (Python regex), severity (low|medium|high),",
    "message, suggestion, flags (any of i,m,s). 'allow' is literal strings to",
    "drop (public names that resemble internal ones)."
  ],
  "rules": [
    {"id": "internal-hostname", "pattern": "\\\\bacme-[a-z]{2,}[0-9]{2,}\\\\b",
     "severity": "high", "message": "internal hostname",
     "suggestion": "use a public codename", "flags": "i"},
    {"id": "private-project", "pattern": "\\\\b(?:project-falcon|widgetizer)\\\\b",
     "severity": "high", "message": "unreleased internal project name",
     "suggestion": "remove the reference"}
  ],
  "allow": ["acme-public-handle"],
  "entropy": {"enabled": false, "severity": "low"}
}
"""


def _do_init(path):
    """Write a starter private rules file and make sure it is gitignored."""
    if os.path.exists(path):
        print(f"predisclose: {path} already exists; leaving it untouched")
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(INIT_TEMPLATE)
        print(f"predisclose: wrote starter private rules -> {path}")
    base = os.path.basename(path)
    gi = ".gitignore"
    try:
        existing = ""
        if os.path.exists(gi):
            with open(gi, "r", encoding="utf-8") as fh:
                existing = fh.read()
        if base not in existing.split():
            with open(gi, "a", encoding="utf-8") as fh:
                if existing and not existing.endswith("\n"):
                    fh.write("\n")
                fh.write(base + "\n")
            print(f"predisclose: added {base} to {gi}")
    except OSError as e:
        print(f"predisclose: could not update {gi}: {e}", file=sys.stderr)
    print("predisclose: edit it with your org's internal identifiers (it stays local).")
    return 0


def _print_text(findings, scanned, label, use_color):
    by_file = {}
    for f in findings:
        by_file.setdefault(f.path, []).append(f)
    for path in sorted(by_file):
        print(f"\n{path}")
        for f in sorted(by_file[path], key=lambda x: (x.line, x.rule_id)):
            sev = f.severity.upper()
            if use_color:
                sev = f"\033[{SEV_COLOR.get(f.severity, '0')}m{sev}\033[0m"
            commit = f" @{f.commit}" if getattr(f, "commit", "") else ""
            ver = f" [verified: {f.verified}]" if getattr(f, "verified", "") else ""
            print(f"  {f.line}:{f.column} [{sev}] {f.rule_id}{commit}{ver}: {f.match}"
                  + (f"  -> {f.suggestion}" if f.suggestion else ""))
    n = len(findings)
    print(f"\npredisclose: {n} finding(s) across {scanned} file(s) scanned ({label}).")


def _emit(findings, scanned, label, fmt, fail_on, use_color):
    relevant = [f for f in findings if severity_at_least(f.severity, fail_on)]
    if fmt == "sarif":
        print(json.dumps(build_sarif(findings), indent=2))
    elif fmt == "md":
        print(build_markdown(findings, scanned, label, fail_on=fail_on,
                             blocking=len(relevant)))
    elif fmt == "json":
        print(json.dumps({
            "label": label, "files_scanned": scanned,
            "finding_count": len(findings),
            "blocking_count": len(relevant), "fail_on": fail_on,
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
    else:
        if findings:
            _print_text(findings, scanned, label, use_color)
        else:
            print(f"predisclose: clean - 0 findings across {scanned} file(s) ({label}).")
        if relevant:
            print(f"predisclose: {len(relevant)} finding(s) at or above '{fail_on}' "
                  f"-> failing.", file=sys.stderr)
    return 1 if relevant else 0


def _add_common(p):
    p.add_argument("--rules", action="append", default=[],
                   help="extra rules JSON file or URL (repeatable). Private/org rules go here.")
    p.add_argument("--no-builtin", action="store_true",
                   help="disable the built-in generic patterns")
    p.add_argument("--fail-on", choices=["low", "medium", "high"], default="medium",
                   help="minimum severity that causes a non-zero exit (default: medium)")
    p.add_argument("--format", choices=["text", "json", "sarif", "md"], default="text")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--notify-webhook", default="", metavar="URL",
                   help="POST a summary to this webhook when findings hit the "
                        "fail threshold (or set PREDISCLOSE_WEBHOOK)")
    p.add_argument("--notify-style", choices=["slack", "discord", "generic"],
                   default=None,
                   help="webhook payload style (default slack, or "
                        "PREDISCLOSE_WEBHOOK_STYLE)")
    p.add_argument("--verify", action="store_true",
                   help="for supported credential types, call the provider to check "
                        "if the secret is live (network; off by default)")
    p.add_argument("--proximity", action="store_true",
                   help="also flag anchorless tokens (Datadog, Algolia, Cloudflare, "
                        "Heroku, JFrog, ...) when a provider keyword is nearby")
    p.add_argument("--presidio", action="store_true",
                   help="add a Microsoft Presidio PII pass (needs predisclose[ai])")
    p.add_argument("--review", action="store_true",
                   help="ask a LOCAL OpenAI-compatible LLM to flag missed leaks "
                        "(configure via PREDISCLOSE_LLM_BASE / PREDISCLOSE_LLM_MODEL)")


def _build_ai_hook(args, allow):
    """Construct the optional per-file AI hook, or None. Imported lazily so the
    zero-dependency core is untouched when the AI flags are not used."""
    if not (getattr(args, "presidio", False) or getattr(args, "review", False)):
        return None
    from . import ai
    return ai.make_hook(args.presidio, args.review, allow)


_AGENT_TAG_COLOR = {"real_leak": "31", "false_positive": "36",
                    "allowlist_candidate": "33"}  # red / cyan / yellow


def _run_agent_cmd(args, rules, allow, root, use_color):
    """Run the scan->triage->act->re-scan loop and print a triage report.
    Exit 1 if any real leak is at or above --fail-on, else 0."""
    from .agent import run_agent
    result = run_agent(args.paths, rules, allow, root=root,
                       max_steps=args.max_steps, apply_allow=args.apply_allow)
    print(f"predisclose agent: {result['steps']} step(s), "
          f"{result['files_scanned']} file(s) scanned.")
    for t in result["triaged"]:
        f, vd = t["finding"], t["verdict"]
        tag = vd["verdict"]
        if use_color:
            tag = f"\033[{_AGENT_TAG_COLOR.get(tag, '0')}m{tag}\033[0m"
        print(f"  {f.path}:{f.line} [{tag} {vd['confidence']:.0%}] "
              f"{f.rule_id}: {f.match}")
        if vd["reason"]:
            print(f"      {vd['reason']}")
        if vd["verdict"] == "real_leak" and vd["action"]:
            print(f"      -> {vd['action']}")
    if result["applied_allow"]:
        print(f"predisclose agent: wrote {len(result['applied_allow'])} allow "
              f"entr(y|ies) to your private rules: "
              f"{', '.join(result['applied_allow'])}")
    if result["proposed_allow"]:
        print("predisclose agent: proposed allowlist entries (re-run with "
              "--apply-allow to write them):")
        for term in result["proposed_allow"]:
            print(f"  + {term}")
    if result["clean"]:
        print("predisclose agent: clean - no findings remain.")
    blocking = [f for f in result["real_leaks"]
                if severity_at_least(f.severity, args.fail_on)]
    # Push only the CONFIRMED real leaks the agent kept - not the false positives
    # or allowlist candidates it filtered out. That noise reduction is the point
    # of routing the agent through the webhook instead of a raw scan.
    webhook = args.notify_webhook or webhook_from_env()
    if webhook and blocking:
        label = f"agent triage ({result['steps']} step(s))"
        notify(webhook, build_summary_text(blocking, result["files_scanned"], label),
               blocking, style=args.notify_style)
    if blocking:
        print(f"predisclose agent: {len(blocking)} real leak(s) at or above "
              f"'{args.fail_on}' -> failing.", file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(prog="predisclose", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"predisclose {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan local files/dirs, git staged content, or history")
    sp.add_argument("paths", nargs="*", default=["."])
    sp.add_argument("--staged", action="store_true", help="scan git staged content")
    sp.add_argument("--history", action="store_true",
                    help="scan every commit in git history (finds removed secrets)")
    sp.add_argument("--since", default=None, metavar="REV",
                    help="with --history, only scan commits in <REV>..HEAD")
    sp.add_argument("--entropy", action="store_true",
                    help="also flag high-entropy strings no pattern matched")
    sp.add_argument("--entropy-threshold", type=float, default=None, metavar="BITS",
                    help="min bits/char for a base64-ish token to count (default 4.0)")
    sp.add_argument("--baseline", default=None, metavar="FILE",
                    help="suppress findings recorded in this baseline; report only new ones")
    sp.add_argument("--update-baseline", action="store_true",
                    help="(re)write the --baseline file from the current findings, then exit")
    _add_common(sp)

    gh = sub.add_parser("github", help="scan published GitHub repos (read-only)")
    gh.add_argument("--org", action="append", default=[])
    gh.add_argument("--user", action="append", default=[])
    gh.add_argument("--repo", action="append", default=[], help="owner/name")
    gh.add_argument("--include-private", action="store_true")
    _add_common(gh)

    ip = sub.add_parser("init", help="write a starter private rules file and gitignore it")
    ip.add_argument("--path", default=".predisclose.local.json",
                    help="where to write the private rules file (default .predisclose.local.json)")

    ag = sub.add_parser("agent",
                        help="autonomous loop: scan, judge each finding with a "
                             "LOCAL model, act, re-scan until clean (needs a local LLM)")
    ag.add_argument("paths", nargs="*", default=["."])
    ag.add_argument("--max-steps", type=int, default=3,
                    help="max scan/triage/re-scan iterations (default 3)")
    ag.add_argument("--apply-allow", action="store_true",
                    help="append allowlist_candidate matches to your PRIVATE rules "
                         "file (.predisclose.local.json); off by default (propose-only)")
    ag.add_argument("--rules", action="append", default=[],
                    help="extra rules JSON file or URL (repeatable). Private/org rules go here.")
    ag.add_argument("--no-builtin", action="store_true",
                    help="disable the built-in generic patterns")
    ag.add_argument("--fail-on", choices=["low", "medium", "high"], default="medium",
                    help="minimum severity of a REAL leak that fails the run (default: medium)")
    ag.add_argument("--notify-webhook", default="", metavar="URL",
                    help="POST a summary of the CONFIRMED real leaks to this webhook "
                         "when any is at or above --fail-on (or set PREDISCLOSE_WEBHOOK)")
    ag.add_argument("--notify-style", choices=["slack", "discord", "generic"],
                    default=None,
                    help="webhook payload style (default slack, or PREDISCLOSE_WEBHOOK_STYLE)")
    ag.add_argument("--no-color", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "init":
        return _do_init(args.path)
    use_color = (not args.no_color) and sys.stdout.isatty() \
        and getattr(args, "format", "text") == "text"

    try:
        scan_root = "."
        if args.cmd == "agent" and args.paths:
            scan_root = args.paths[0]
        elif args.cmd == "scan" and not args.staged and not args.history and args.paths:
            scan_root = args.paths[0]
        rules, allow = load_rules(args.rules, use_builtin=not args.no_builtin,
                                  scan_root=scan_root)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"predisclose: rule load error: {e}", file=sys.stderr)
        return 2
    if not rules and not (args.cmd == "scan" and args.entropy):
        print("predisclose: no rules loaded (used --no-builtin with no --rules?)",
              file=sys.stderr)
        return 2

    if args.cmd == "agent":
        return _run_agent_cmd(args, rules, allow, scan_root, use_color)

    ai_hook = _build_ai_hook(args, allow)

    if args.cmd == "scan":
        if args.staged and args.history:
            print("predisclose: choose either --staged or --history, not both",
                  file=sys.stderr)
            return 2
        if args.since and not args.history:
            print("predisclose: --since has no effect without --history",
                  file=sys.stderr)
        entropy_opts = load_entropy_options(
            cli_enabled=args.entropy, cli_threshold=args.entropy_threshold,
            extra_paths=args.rules, scan_root=scan_root)
        if args.history:
            findings, commits, scanned, herr = scan_history(
                rules, allow, since=args.since, entropy_opts=entropy_opts,
                proximity=args.proximity)
            if herr:
                print(f"predisclose: history scan error: {herr}", file=sys.stderr)
                return 2
            label = f"{commits} commit(s)"
        elif args.staged:
            findings, scanned = scan_staged(rules, allow, entropy_opts=entropy_opts,
                                            ai_hook=ai_hook, proximity=args.proximity)
            label = "git staged"
        else:
            findings, scanned = scan_paths(args.paths, rules, allow, root=scan_root,
                                           entropy_opts=entropy_opts, ai_hook=ai_hook,
                                           proximity=args.proximity)
            label = "filesystem"
    else:  # github
        if not (args.org or args.user or args.repo):
            print("predisclose github: need --org, --user, or --repo", file=sys.stderr)
            return 2
        findings, repos, scanned, errors = scan_github(
            rules, allow, args.org, args.user, args.repo, args.include_private,
            ai_hook=ai_hook)
        label = f"{repos} repo(s)"
        for e in errors[:10]:
            print(f"predisclose: scan note: {e}", file=sys.stderr)

    if args.cmd == "scan" and getattr(args, "baseline", None):
        from .baseline import load_baseline, write_baseline, filter_new
        if args.update_baseline:
            n = write_baseline(args.baseline, findings)
            print(f"predisclose: wrote baseline with {n} fingerprint(s) -> {args.baseline}")
            return 0
        base, berr = load_baseline(args.baseline)
        if berr:
            print(f"predisclose: baseline load error: {berr}", file=sys.stderr)
            return 2
        before = len(findings)
        findings = filter_new(findings, base)
        label += f" vs baseline ({before - len(findings)} known suppressed)"

    if getattr(args, "verify", False) and findings:
        from .verify import verify_findings
        vc = verify_findings(findings)
        if vc.get("active"):
            print(f"predisclose: {vc['active']} finding(s) VERIFIED ACTIVE, live "
                  f"credential(s), rotate now.", file=sys.stderr)

    rc = _emit(findings, scanned, label, args.format, args.fail_on, use_color)

    # Push a notification when findings hit the fail threshold (rc == 1). Opt-in:
    # only fires if a webhook is configured. Never changes the exit code.
    webhook = args.notify_webhook or webhook_from_env()
    if webhook and rc == 1:
        notify(webhook, build_summary_text(findings, scanned, label),
               findings, style=args.notify_style)
    return rc


if __name__ == "__main__":
    sys.exit(main())
