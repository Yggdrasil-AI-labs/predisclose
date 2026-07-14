#!/usr/bin/env python3
"""Build a single-file, zero-dependency ``predisclose.pyz`` (stdlib zipapp).

The core of predisclose is pure standard library, so the whole tool ships as one
executable zip archive you can copy to any machine with Python 3.8+ and run
directly, with no pip install, no virtualenv, and no compiled binary:

    python predisclose.pyz scan .

That makes it a practical last-mile scrub in ephemeral environments (a Colab
cell, an agent scratchpad, a bare container) where installing a package is
friction. The archive is plain Python you can unzip and read end to end.

Only the stdlib core is guaranteed to run from the .pyz. The optional AI layers
(``--presidio`` / ``--review``) still need the ``predisclose[ai]`` extra present
in the ambient environment; they degrade gracefully when it is absent.

Usage:
    python scripts/build_pyz.py                 # -> dist/predisclose.pyz
    python scripts/build_pyz.py -o out.pyz
"""
import argparse
import os
import shutil
import tempfile
import zipapp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "predisclose")

# A top-level __main__.py that PROPAGATES the CLI exit code. zipapp's own
# ``main="pkg:fn"`` generator calls the function but discards its return value,
# which would make the archive always exit 0 and silently never gate a CI job or
# block a commit. Shipping our own entry point avoids that.
ENTRY = (
    "import sys\n"
    "from predisclose.cli import main\n"
    "sys.exit(main())\n"
)


def build(out_path):
    """Stage the package plus an exit-code-propagating entry point, then zip it."""
    with tempfile.TemporaryDirectory() as staging:
        # zipapp archives a *source directory*; stage the package inside it so the
        # archive root holds ``predisclose/`` importable as a package.
        shutil.copytree(
            PKG,
            os.path.join(staging, "predisclose"),
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        with open(os.path.join(staging, "__main__.py"), "w", encoding="utf-8") as fh:
            fh.write(ENTRY)
        out_dir = os.path.dirname(os.path.abspath(out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        # No main= here: we ship our own __main__.py above so sys.exit runs.
        zipapp.create_archive(
            staging, target=out_path,
            interpreter="/usr/bin/env python3", compressed=True,
        )
    return out_path


def main():
    ap = argparse.ArgumentParser(description="Build a single-file predisclose.pyz")
    ap.add_argument("-o", "--output",
                    default=os.path.join(ROOT, "dist", "predisclose.pyz"),
                    help="output path (default: dist/predisclose.pyz)")
    args = ap.parse_args()
    path = build(args.output)
    print(f"built {path} ({os.path.getsize(path):,} bytes)")


if __name__ == "__main__":
    main()
