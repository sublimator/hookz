"""Provenance pin for the build flags hookz reproduces.

hookz's guard checker tells you whether xahaud would accept a binary. That
answer is only meaningful for the binary people actually deploy, and the binary
depends on the toolchain that produced it — the same source, compiled two
defensible ways, differs by 8 levels of block nesting, which is the difference
between installing and being rejected outright.

So the flags are not ours to choose. They are copied from the official web
compiler, and this module records exactly which revision they were copied from.
`hookz.wasm.optimize.LOCAL_STRUCTURAL` and
`hookz.wasm.pipeline.LOCAL_STRUCTURAL_PIPELINE` are the local approximation;
this is the citation. Actual service compilation is `hookz build --buildbox`.

PIN
---
Repo    https://github.com/Xahau/xrpl-hooks-compiler
Source  compiler-api/src/chooks.ts — `get_optimization_options()`,
        `get_clang_options()`, `get_lld_options()`, `link_c_files()`,
        `optimize_wasm()`
Ref     6a954d4f303687c543ae1c85019c3516b8c454bb  (2025-02-14, "Use Xahau
        Submodule", PR #38)
Browse  https://github.com/Xahau/xrpl-hooks-compiler/blob/6a954d4f303687c543ae1c85019c3516b8c454bb/compiler-api/src/chooks.ts

THE WINDOW MATTERS
------------------
That commit introduced a fixed, aggressive binaryen pass list applied to every
build. It was reverted on 2026-07-09 by

    61f3a0798a0ca584c8d8954b59ea6c991f334e18  "Revert optimizaion changes
    (6a954d4) (#51)"

which replaced it with caller-supplied `-O1..-O4/-Os` and a default of `-O0`,
and dropped the wasm-opt pass list entirely.

So hooks built between 2025-02-14 and 2026-07-09 carry the pass list; hooks
built after do not. A hook deployed inside that window needs these flags to
reproduce, which is how the list was found. A hook built today through the
current web compiler will NOT match this profile.

WHY --rereloop IS SINGLED OUT
-----------------------------
Ablation over the pass list, holding the source and clang invocation fixed.
One row decides anything, and it is not a size:

    minus --rereloop      block depth rises past xahaud's limit of 16,
                          and SetHook refuses the install
    every other flag      depth unchanged; size moves by well under a percent

Absolute sizes and depths are deliberately not recorded. They are properties
of whichever binary happened to be measured rather than of the flag list, and
a size-and-depth pair identifies a specific deployed contract to anyone who
can rebuild from its published source. The argument for --rereloop needs
neither number.

`--rereloop` reruns binaryen's Relooper over the control flow and is the only
pass that moves nesting; everything else is size and speed. It requires flat
IR, so `--flatten` must precede it.

It is not a flattener. On small hooks it costs a level or two (treasury.c
3 -> 4, govern.c 9 -> 11); on a large deeply-nested one it collapses the tree
by something like eight levels. The direction is not to be reasoned about — the
deployed binary is the restructured one, so hookz runs what the reference runs.

Dropping the optimizer is therefore not a graceful degradation: it produces a
depth the deployed toolchain never emits, which is why `hookz build` fails
rather than continues when wasm-opt is absent.

KNOWN DIVERGENCES FROM THE REFERENCE BUILD
------------------------------------------
hookz reproduces the flags, not the binaries that consume them. Rebuilding a
deployed hook from its published source has landed within ~0.4% on size and
~1% on worst-case execution, at identical block depth. The residue is
toolchain versions:

1. clang. The buildbox builds its own from a patched LLVM 15 (submodule
   `llvm-project` @ 4ca7eaabf2b3d617f9bb9490ac07ed4055fe80f9, whose HEAD is
   "Guard call with non-const integer param checker"). hookz uses whatever
   wasi-sdk is configured — wasi-sdk 32 is clang 22.
2. binaryen. Not pinned in-repo; `docker/Dockerfile` does `COPY wasm-opt
   /usr/bin` from an image built elsewhere. Measurements above used 128.
3. hook-cleaner. hookz ports it (`clean.py`); the buildbox shells out to
   `hook-cleaner-c` @ b856a3614c00361f108d07379f5892e7347bb994.

Byte-identical reproduction would need all three pinned. Structural
reproduction — the thing SetHook actually judges — does not.

OTHER SUBMODULE PINS AT THIS REVISION
-------------------------------------
    compiler-api/clang/includes  bb244ef7729503a0317bcff0f8fdaa93ca5cb7d2
    guard-checker                de69e8aa054d49612dda7046962003beb88c0749
    hook-cleaner-c               b856a3614c00361f108d07379f5892e7347bb994
    llvm-project                 4ca7eaabf2b3d617f9bb9490ac07ed4055fe80f9
    wasi-sdk                     628938fa7156e3c709cb7f8fce5c01976b7d3ed4

The `clang/includes` pin is the same xahaud commit hookz ports its guard
checker from — see `xahaud_ref.XAHAUD_COMMIT`. That alignment is a coincidence
of timing, not a guarantee.
"""

from __future__ import annotations

COMPILER_REPO = "https://github.com/Xahau/xrpl-hooks-compiler"
COMPILER_SOURCE = "compiler-api/src/chooks.ts"

# The revision the local-structural flags were copied from.
COMPILER_COMMIT = "6a954d4f303687c543ae1c85019c3516b8c454bb"
COMPILER_COMMIT_DATE = "2025-02-14"

# The revision that removed them again. Builds after this date use a different
# toolchain and will not match local-structural.
REVERTED_IN = "61f3a0798a0ca584c8d8954b59ea6c991f334e18"
REVERTED_DATE = "2026-07-09"

# Toolchain the reference build used, for the record. hookz does not pin these
# — see KNOWN DIVERGENCES above.
LLVM_PROJECT_COMMIT = "4ca7eaabf2b3d617f9bb9490ac07ed4055fe80f9"  # patched LLVM 15
WASI_SDK_COMMIT = "628938fa7156e3c709cb7f8fce5c01976b7d3ed4"
HOOK_CLEANER_COMMIT = "b856a3614c00361f108d07379f5892e7347bb994"
GUARD_CHECKER_COMMIT = "de69e8aa054d49612dda7046962003beb88c0749"


def permalink(line: int | None = None) -> str:
    """GitHub URL for chooks.ts at the commit the flags came from."""
    url = f"{COMPILER_REPO}/blob/{COMPILER_COMMIT}/{COMPILER_SOURCE}"
    return f"{url}#L{line}" if line else url


def cite() -> str:
    """One-line citation, for CLI output and error messages."""
    return (f"{COMPILER_SOURCE} @ {COMPILER_COMMIT[:8]} "
            f"({COMPILER_COMMIT_DATE}, reverted {REVERTED_DATE})")
