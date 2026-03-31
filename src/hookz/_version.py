"""Version string with git commit and dirty state."""

from __future__ import annotations

import hashlib
import subprocess
from functools import lru_cache
from pathlib import Path

_PACKAGE_VERSION = "0.1.0"
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@lru_cache(maxsize=1)
def get_version() -> str:
    """Return version string: 0.1.0+g<short_sha>[.dirty.<diff_hash>]"""
    try:
        sha = subprocess.run(
            ["git", "-C", str(_REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if not sha:
            return _PACKAGE_VERSION

        dirty = subprocess.run(
            ["git", "-C", str(_REPO_ROOT), "diff", "--quiet", "HEAD"],
            capture_output=True, timeout=5,
        ).returncode != 0

        version = f"{_PACKAGE_VERSION}+g{sha}"
        if dirty:
            diff = subprocess.run(
                ["git", "-C", str(_REPO_ROOT), "diff", "HEAD"],
                capture_output=True, timeout=5,
            ).stdout
            diff_hash = hashlib.sha1(diff).hexdigest()[:8]
            version += f".dirty.{diff_hash}"

        return version
    except Exception:
        return _PACKAGE_VERSION
