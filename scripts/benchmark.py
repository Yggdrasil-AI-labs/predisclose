#!/usr/bin/env python3
"""Reproducible benchmark: predisclose vs gitleaks on a third-party corpus.

A file-level recall proxy on a planted-secret corpus. Point it at a checkout of
a public planted-secret repo (built for Plazmaz/leaky-repo). It runs predisclose
(deterministic, and with the opt-in --proximity/--entropy passes) and, if
gitleaks is on PATH, gitleaks too, then prints how many files each tool flagged
and which files only one of them caught.

    git clone https://github.com/Plazmaz/leaky-repo
    python scripts/benchmark.py leaky-repo

The number is a coarse recall proxy: whether the tool flagged ANY secret in a
file, not per-secret precision/recall against labeled ground truth.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys


def _rel(path, corpus):
    ap, ac = os.path.abspath(path), os.path.abspath(corpus)
    return os.path.relpath(ap, ac) if ap.startswith(ac) else path


def run_predisclose(corpus, extra):
    cmd = [sys.executable, "-m", "predisclose", "scan", corpus,
           "--format", "json"] + extra
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data.get("findings", data) if isinstance(data, dict) else data


def run_gitleaks(corpus):
    if not shutil.which("gitleaks"):
        return None
    rpt = os.path.abspath(os.path.join(corpus, os.pardir, "_gl_bench.json"))
    subprocess.run(["gitleaks", "dir", corpus, "--report-format", "json",
                    "--report-path", rpt, "--no-banner", "--exit-code", "0"],
                   capture_output=True, text=True)
    try:
        return json.load(open(rpt)) if os.path.exists(rpt) else []
    finally:
        if os.path.exists(rpt):
            os.remove(rpt)


def files_of(findings, key, corpus):
    return {_rel(str(f.get(key, "")), corpus) for f in findings}


def main():
    ap = argparse.ArgumentParser(description="predisclose vs gitleaks file-level benchmark")
    ap.add_argument("corpus", help="path to a planted-secret corpus checkout")
    args = ap.parse_args()

    pd = run_predisclose(args.corpus, [])
    pdf = run_predisclose(args.corpus, ["--proximity", "--entropy"])
    gl = run_gitleaks(args.corpus)

    pd_files, pdf_files = files_of(pd, "path", args.corpus), files_of(pdf, "path", args.corpus)
    print("predisclose default:            %3d findings / %2d files" % (len(pd), len(pd_files)))
    print("predisclose +proximity+entropy: %3d findings / %2d files" % (len(pdf), len(pdf_files)))
    if gl is None:
        print("gitleaks: not on PATH, skipped")
        return 0
    gl_files = files_of(gl, "File", args.corpus)
    print("gitleaks:                       %3d findings / %2d files" % (len(gl), len(gl_files)))
    print()
    print("caught by gitleaks, missed by predisclose(full):",
          sorted(gl_files - pdf_files) or "none")
    print("caught by predisclose(full), missed by gitleaks:",
          sorted(pdf_files - gl_files) or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
