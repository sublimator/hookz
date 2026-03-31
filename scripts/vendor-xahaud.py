#!/usr/bin/env python3
"""Vendor xahaud source files into xahaud-lite/.

Usage:
    # From a local checkout:
    python scripts/vendor-xahaud.py ~/projects/xahaud

    # From a git ref (fetches from origin):
    python scripts/vendor-xahaud.py ~/projects/xahaud --ref origin/develop
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# Import just the enum — avoid pulling in the full hookz package (wasmtime etc.)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Direct import of the single module, bypassing hookz/__init__.py
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "xahaud_files",
    Path(__file__).resolve().parent.parent / "src" / "hookz" / "xahaud_files.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
XahaudFile = _mod.XahaudFile


DEST = Path(__file__).resolve().parent.parent / "src" / "hookz" / "xahaud_lite"


def vendor_from_tree(root: Path) -> None:
    """Copy all XahaudFile entries from root into xahaud-lite/."""
    copied = 0
    missing = []

    for f in XahaudFile:
        src = root / f.value
        dst = DEST / f.value

        if not src.exists():
            missing.append(f)
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
        print(f"  {f.value}")

    print(f"\n{copied} files vendored to {DEST}")
    if missing:
        print(f"\n{len(missing)} missing (not fatal — may not exist on this branch):")
        for f in missing:
            print(f"  {f.name}: {f.value}")


def vendor_from_ref(repo: Path, ref: str) -> None:
    """Extract files from a git ref without checking it out."""
    copied = 0
    missing = []

    for f in XahaudFile:
        dst = DEST / f.value
        dst.parent.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{f.value}"],
            capture_output=True,
        )

        if result.returncode != 0:
            missing.append(f)
            continue

        dst.write_bytes(result.stdout)
        copied += 1
        print(f"  {f.value}")

    print(f"\n{copied} files vendored from {ref} to {DEST}")
    if missing:
        print(f"\n{len(missing)} missing (not fatal — may not exist on this branch):")
        for f in missing:
            print(f"  {f.name}: {f.value}")


def main():
    parser = argparse.ArgumentParser(description="Vendor xahaud files into xahaud-lite/")
    parser.add_argument("xahaud_root", type=Path, help="Path to xahaud repo")
    parser.add_argument("--ref", default=None, help="Git ref to extract from (e.g. origin/develop)")
    args = parser.parse_args()

    root = args.xahaud_root.expanduser().resolve()
    if not root.exists():
        print(f"Error: {root} does not exist")
        sys.exit(1)

    if args.ref:
        # Fetch first to ensure ref is up to date
        print(f"Fetching {args.ref.split('/')[0]}...")
        subprocess.run(["git", "-C", str(root), "fetch", args.ref.split("/")[0]], check=False)
        print(f"\nVendoring from {args.ref}:")
        vendor_from_ref(root, args.ref)
    else:
        print(f"Vendoring from working tree {root}:")
        vendor_from_tree(root)


if __name__ == "__main__":
    main()
