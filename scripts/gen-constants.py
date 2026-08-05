#!/usr/bin/env python3
"""Regenerate the checked-in constant modules from a xahaud source tree.

Usage:
    python scripts/gen-constants.py [XAHAUD_ROOT] [--hookapi]

Without XAHAUD_ROOT the tree is resolved through hookz's ordinary config
(`[paths].xahaud` in hookz.toml, HOOKZ_XAHAUD, or the vendored fallback).

Writes:
    src/hookz/ter.py     — TER codes            (include/xrpl/protocol/TER.h)
    src/hookz/flags.py   — tf*/asf*/lsf* flags  (TxFlags.h, LedgerFormats.h)
    src/hookz/hookapi.py — only with --hookapi  (hook/*.h #defines)

Every generated constant carries an `xahaud:<path>:<line>` citation into the
tree it was read from; the module headers record the tree's commit. Commit the
regenerated files together with a note of the xahaud ref they came from.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xahaud_root", nargs="?", default=None,
                        help="path to a xahaud checkout")
    parser.add_argument("--hookapi", action="store_true",
                        help="also regenerate src/hookz/hookapi.py")
    args = parser.parse_args()

    if args.xahaud_root is None:
        from hookz.config import load_config
        root = load_config().xahaud_root
        if not root or not Path(root).exists():
            parser.error("no xahaud tree configured; pass XAHAUD_ROOT")
    else:
        root = args.xahaud_root

    from hookz.xrpl.xahaud import XahaudRepo
    repo = XahaudRepo(root)

    out = REPO / "src" / "hookz"
    repo.generate_ter_py(out / "ter.py")
    print(f"wrote {out / 'ter.py'}")
    repo.generate_flags_py(out / "flags.py")
    print(f"wrote {out / 'flags.py'}")
    if args.hookapi:
        repo.generate_hookapi_py(out / "hookapi.py")
        print(f"wrote {out / 'hookapi.py'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
