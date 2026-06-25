"""Git-history scanning (the `--history` front-end). Stdlib only; shells out to git.

Walks commits oldest-first and scans the version of each changed file as it
existed in that commit, so a secret that was committed and later removed is still
found. Each finding carries the short SHA of the earliest commit it was seen in,
its path, and its line. Identical findings that survive across many commits are
reported once.
"""
import subprocess

from .engine import scan_text
from .entropy import entropy_findings
from .proximity import proximity_findings
from .fsscan import is_text, load_ignore, _ignored


def _git(args, cwd="."):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True,
                          text=True, errors="replace")


def is_git_repo(cwd="."):
    r = _git(["rev-parse", "--is-inside-work-tree"], cwd)
    return r.returncode == 0 and r.stdout.strip() == "true"


def commit_shas(since=None, cwd="."):
    """Oldest-first list of commit SHAs. With `since` (a rev), only commits in
    <since>..HEAD; otherwise every commit reachable from HEAD."""
    rng = ["%s..HEAD" % since] if since else ["HEAD"]
    r = _git(["rev-list", "--reverse"] + rng, cwd)
    if r.returncode != 0:
        return [], (r.stderr.strip() or "git rev-list failed")
    return [s for s in r.stdout.split("\n") if s.strip()], None


def _changed_files(sha, cwd="."):
    r = _git(["diff-tree", "--no-commit-id", "--name-only", "-r", "--root",
              "--diff-filter=ACMR", sha], cwd)
    if r.returncode != 0:
        return []
    return [f for f in r.stdout.split("\n") if f.strip()]


def _blob(sha, path, cwd="."):
    r = _git(["show", "%s:%s" % (sha, path)], cwd)
    if r.returncode != 0:
        return None
    return r.stdout


def scan_history(rules, allow, since=None, cwd=".", entropy_opts=None, proximity=False):
    """Returns (findings, commits_scanned, files_scanned, error_or_None)."""
    if not is_git_repo(cwd):
        return [], 0, 0, "not a git repository"
    shas, err = commit_shas(since, cwd)
    if err:
        return [], 0, 0, err
    ignore = load_ignore(cwd)
    findings = []
    seen = set()
    files_scanned = 0
    for sha in shas:
        short = sha[:10]
        for path in _changed_files(sha, cwd):
            if not is_text(path) or _ignored(path, cwd, ignore):
                continue
            text = _blob(sha, path, cwd)
            if text is None:
                continue
            files_scanned += 1
            file_findings = scan_text(text, rules, allow, path=path)
            if entropy_opts and entropy_opts.enabled:
                file_findings += entropy_findings(text, allow, path,
                                                  entropy_opts, file_findings)
            if proximity:
                file_findings += proximity_findings(text, allow, path, file_findings)
            for f in file_findings:
                key = (f.rule_id, f.path, f.line, f.column, f.match)
                if key in seen:
                    continue
                seen.add(key)
                f.commit = short
                findings.append(f)
    return findings, len(shas), files_scanned, None
