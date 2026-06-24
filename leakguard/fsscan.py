"""Filesystem + git-staged scanning (the pre-commit / CI front-end). Stdlib only."""
import fnmatch
import os
import subprocess

from .engine import scan_text
from .entropy import entropy_findings

IGNORE_FILE = ".leakguardignore"

TEXT_EXT = {
    ".md", ".markdown", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".toml", ".txt", ".text",
    ".rst", ".sh", ".bash", ".zsh", ".cfg", ".ini", ".conf", ".cnf", ".env",
    ".html", ".htm", ".css", ".csv", ".tsv", ".go", ".rs", ".java", ".kt",
    ".kts", ".scala", ".c", ".h", ".cpp", ".cs", ".rb", ".php", ".pl", ".lua",
    ".dart", ".swift", ".sql", ".xml", ".svg", ".properties", ".log", ".eml",
    ".tf", ".tfvars", ".hcl", ".gradle", ".groovy", ".vue", ".svelte", ".ps1",
    ".psm1", ".bat", ".cmd", ".pem", ".key", ".crt", ".cer", ".pub", ".ovpn",
}
TEXT_NAMES = {"readme", "license", "dockerfile", "containerfile", "makefile",
              "changelog", ".gitignore", ".dockerignore", "requirements.txt",
              ".env.example", ".npmrc", ".netrc", ".pgpass", ".htpasswd"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".mypy_cache", ".pytest_cache", ".idea"}
MAX_BYTES = 800_000


def is_text(path):
    base = os.path.basename(path).lower()
    if base in TEXT_NAMES or base.startswith(("readme", "license")):
        return True
    _, ext = os.path.splitext(base)
    return ext in TEXT_EXT


def _read(path):
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return None


def load_ignore(root="."):
    """Read .leakguardignore (fnmatch globs, one per line, # comments)."""
    pats = []
    try:
        with open(os.path.join(root, IGNORE_FILE), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    pats.append(line.rstrip("/"))
    except OSError:
        pass
    return pats


def _ignored(path, root, patterns):
    if not patterns:
        return False
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    base = os.path.basename(path)
    for pat in patterns:
        if (fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(base, pat)
                or rel == pat or rel.startswith(pat + "/")):
            return True
    return False


def iter_paths(paths, root=".", ignore=None):
    ignore = ignore or []
    for p in paths:
        if os.path.isfile(p):
            if not _ignored(p, root, ignore):
                yield p
        elif os.path.isdir(p):
            for cur, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS
                           and not _ignored(os.path.join(cur, d), root, ignore)]
                for f in files:
                    fp = os.path.join(cur, f)
                    if not _ignored(fp, root, ignore):
                        yield fp


def _scan_one(text, rules, allow, path, entropy_opts=None, ai_hook=None):
    findings = scan_text(text, rules, allow, path=path)
    if entropy_opts and entropy_opts.enabled:
        findings += entropy_findings(text, allow, path, entropy_opts, findings)
    if ai_hook is not None:
        findings = findings + ai_hook(text, path, findings)
    return findings


def scan_paths(paths, rules, allow, root=".", entropy_opts=None, ai_hook=None):
    ignore = load_ignore(root)
    findings = []
    scanned = 0
    for path in iter_paths(paths, root, ignore):
        if not is_text(path):
            continue
        text = _read(path)
        if text is None:
            continue
        scanned += 1
        findings.extend(_scan_one(text, rules, allow, path, entropy_opts, ai_hook))
    return findings, scanned


def _git(args, cwd="."):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)


def staged_files(cwd="."):
    r = _git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], cwd)
    return [f for f in r.stdout.split("\0") if f]


def scan_staged(rules, allow, cwd=".", entropy_opts=None, ai_hook=None):
    """Scan the STAGED content of files about to be committed (pre-commit use)."""
    findings = []
    scanned = 0
    for f in staged_files(cwd):
        if not is_text(f):
            continue
        blob = _git(["show", f":{f}"], cwd)
        if blob.returncode != 0:
            continue
        scanned += 1
        findings.extend(_scan_one(blob.stdout, rules, allow, f, entropy_opts, ai_hook))
    return findings, scanned
