"""Provenance pin for the xahaud sources hookz ports.

hookz's guard checker, cleaner and API whitelist are ports of C++ that lives
in xahaud. When that C++ moves, the port silently stops matching the network —
and a guard checker that disagrees with the real one is worse than none,
because it hands out false verdicts with confidence.

This module records exactly which revision was ported, so a future reader can
tell "still current" from "drifted" without re-deriving it. `check_drift()`
answers that question against whatever checkout hookz is configured to use;
`hookz doctor` reports it.

PIN
---
Repo    https://github.com/Xahau/xahaud
Ref     origin/dev @ bb244ef7729503a0317bcff0f8fdaa93ca5cb7d2  (2026-06-21)
Browse  https://github.com/Xahau/xahaud/blob/bb244ef7729503a0317bcff0f8fdaa93ca5cb7d2/include/xrpl/hook/Guard.h

Pinned to upstream `dev` deliberately. Do NOT re-pin to a local worktree or a
feature branch: those carry unmerged patches, and porting against one bakes
non-network behaviour into hookz. This pin was set after discovering the
`xahaud-wasm-coverage` worktree was simultaneously *behind* dev (missing
fixGuardDepth32, xahaud PR #653) and *ahead* of it (a local coverage patch
relaxing the function-type result_count rule).

Citations elsewhere in hookz are written as `Guard.h:NNN` / `Enum.h:NNN` and
refer to THESE files at THIS commit. If you re-pin, the line numbers move.

KNOWN DELIBERATE DIVERGENCES
----------------------------
1. Coverage builds. Upstream requires every function type to declare exactly
   one result (Guard.h:1440ish). hookz permits the void `__on_source_line`
   import, but only when a caller passes `get_import_signatures(coverage=True)`
   — i.e. for instrumented binaries, which are never deployed. Production
   builds get upstream's rule because no real hook API returns void.
2. Waived limits. The `--ignore-*` flags let analysis continue past a limit
   xahaud enforces. Anything waived is recorded in `GuardResult.waived` and
   makes `deployable` False.

KNOWN GAPS — hookz ACCEPTS what xahaud REJECTS (false green lights)
------------------------------------------------------------------
Confirmed by differential testing against a checker built from the pinned
Guard.h. Each is a hook hookz would pass and SetHook would refuse:
  - unknown/illegal opcodes are skipped rather than rejected  (Guard.h:789)
  - reftype and select-t operand types unvalidated            (Guard.h:~538)
  - invalid local types unvalidated                           (Guard.h:~1502)
  - section order and duplicate sections unchecked            (Guard.h:~914)
Fixing these is the highest-value work left in the port.

RE-VERIFYING
------------
The differential harness used throughout is a standalone build of the pinned
Guard.h — the headers carry a `GUARD_CHECKER_BUILD` ifdef for exactly this:

    git show origin/dev:include/xrpl/hook/Guard.h        > Guard.h
    git show origin/dev:include/xrpl/hook/Enum.h         > Enum.h
    git show origin/dev:include/xrpl/hook/hook_api.macro > hook_api.macro
    g++ -o guard_checker guard_checker.cpp --std=c++17 -DGUARD_CHECKER_BUILD

`getImportWhitelist()` can be dumped the same way and diffed against
`whitelist.get_import_signatures(coverage=True)`; they are expected to be
byte-identical across all 76 entries.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

XAHAUD_REPO = "https://github.com/Xahau/xahaud"
XAHAUD_REF = "dev"  # identical to `release` at this commit
XAHAUD_COMMIT = "bb244ef7729503a0317bcff0f8fdaa93ca5cb7d2"
XAHAUD_COMMIT_DATE = "2026-06-21"

# The vendored tree under src/hookz/xahaud_lite/ IS the reference copy: every
# file there was taken verbatim from XAHAUD_COMMIT at the same relative path.
# It is what hookz falls back to when no checkout is configured, and what the
# `Guard.h:NNN` citations refer to. Re-vendor with:
#
#   git -C <xahaud> show "<commit>:<path>" > src/hookz/xahaud_lite/<path>
#
# Files whose behaviour is ported (not merely shipped for `hookz show`).
# Changing any of these means re-checking the port against the new C++.
PORTED_FILES = (
    "include/xrpl/hook/Guard.h",        # guard.py
    "include/xrpl/hook/Enum.h",         # guard.py limits, whitelist.py type codes
    "include/xrpl/hook/hook_api.macro",  # whitelist.py
)

# Files hookz does not port but makes claims *about*, by line, via `xahaud:`
# citations. Vendored for a narrower reason than PORTED_FILES: so a citation
# can be checked and read without a network round trip, and so a re-pin turns a
# moved line into a failing check rather than a comment that quietly stops
# being true. Drift here means a citation may have moved; drift in
# PORTED_FILES means ported *behaviour* may have changed, which is worse.
#
# The rule enforces itself — cite a file that is not here and
# `check_citations()` fails until it is vendored.
CITED_FILES = (
    "src/xrpld/app/hook/detail/HookAPI.cpp",      # emission.py, the emit rules
    "src/xrpld/app/hook/detail/applyHook.cpp",    # handler behaviour notes
    "src/xrpld/app/hook/applyHook.h",             # hasCallback
    "src/xrpld/app/tx/detail/SetSignerList.cpp",  # emission.py, SignerListSet preflight
    "src/libxrpl/protocol/STObject.cpp",          # xrpl/txn_parser.py, the (9,9) NOP
    "src/libxrpl/protocol/STTx.cpp",              # emission.py, isPseudoTx
    "include/xrpl/protocol/STTx.h",               # emission.py, maxMultiSigners
    "src/libxrpl/protocol/Feature.cpp",           # amendments.py, the naming rule
    "include/xrpl/protocol/detail/features.macro",  # amendments.py, the name index
)


def vendored_root() -> Path:
    from hookz.xahaud_files import _vendored_root
    return _vendored_root()


def permalink(rel_path: str, line: int | None = None) -> str:
    """GitHub URL for a vendored file at the commit it came from."""
    url = f"{XAHAUD_REPO}/blob/{XAHAUD_COMMIT}/{rel_path}"
    return f"{url}#L{line}" if line else url


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Citations
# ---------------------------------------------------------------------------
#
# A claim about upstream is written in one form, everywhere:
#
#     xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:794
#
# Repo-relative path, a line, and a scheme prefix that makes it greppable. It
# reads as a citation to a human, resolves to a permalink at XAHAUD_COMMIT for
# anyone who wants the source, and `check_citations()` verifies it still points
# where it claims — so a re-pin turns citation rot into a test failure rather
# than a comment that quietly stops being true.
#
# The old bare form (`Guard.h:293`) is still around and still readable, but it
# names no repository and no commit, so it cannot be checked and cannot be
# followed without knowing this module exists.

CITATION = re.compile(r"xahaud:([A-Za-z0-9_./\-]+):(\d+)")


@dataclass(frozen=True)
class Citation:
    path: str          # repo-relative, e.g. src/xrpld/app/hook/detail/HookAPI.cpp
    line: int

    def __str__(self) -> str:
        return f"xahaud:{self.path}:{self.line}"

    @property
    def url(self) -> str:
        return permalink(self.path, self.line)

    def snippet(self, context: int = 0) -> str:
        """What the vendored copy actually says there.

        The point of a citation you can resolve locally: an agent reading the
        port can see the upstream line without a network round trip, and a
        reviewer can tell at a glance whether the claim beside it is true.
        """
        source = vendored_root() / self.path
        if not source.exists():
            return f"<{self.path} is not vendored>"
        lines = source.read_text(errors="replace").splitlines()
        lo = max(0, self.line - 1 - context)
        hi = min(len(lines), self.line + context)
        return "\n".join(lines[lo:hi])


def cite(path: str, line: int) -> Citation:
    return Citation(path=path, line=line)


def parse_citations(text: str) -> list[Citation]:
    """Every `xahaud:path:line` in a blob of text."""
    return [Citation(path=m.group(1), line=int(m.group(2)))
            for m in CITATION.finditer(text)]


def _line_of(path: Path, line: int) -> str | None:
    lines = path.read_text(errors="replace").splitlines()
    return lines[line - 1] if 1 <= line <= len(lines) else None


def checkout_commit(root: Path | str) -> str | None:
    """The commit a checkout is actually at, or None if it is not a git tree."""
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
    except Exception:                                      # noqa: BLE001
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def file_at_pin(root: Path | str, rel_path: str,
                commit: str = XAHAUD_COMMIT) -> str | None:
    """A file's contents at the pinned commit, read out of a checkout.

    `git show <commit>:<path>` rather than reading the working tree. The
    working tree is wherever the developer left it, so comparing against it
    reports drift that means nothing — a branch, a bisect, an unrelated
    feature. The pin is a fixed point, and any checkout containing it can
    produce exactly the bytes hookz was written against.

    Returns None when the checkout does not have that commit, which is a fact
    about the checkout rather than a problem with the citation.
    """
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(root), "show", f"{commit}:{rel_path}"],
                             capture_output=True, text=True, timeout=20)
    except Exception:                                      # noqa: BLE001
        return None
    return out.stdout if out.returncode == 0 else None


@dataclass(frozen=True)
class VendorCheck:
    """Whether the vendored copies were verified, and what came of it.

    `problems` alone cannot answer the question: an empty list means "every
    file matches the pin" *or* "nothing could be checked", and a caller that
    treats both as success has exactly the false green light this module
    exists to prevent. `verified` says which.
    """
    verified: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()
    reason: str = ""

    @property
    def ok(self) -> bool:
        """Something was checked, and all of it matched."""
        return bool(self.verified) and not self.problems

    def __bool__(self) -> bool:
        return self.ok

    def __str__(self) -> str:
        if self.problems:
            return "; ".join(self.problems)
        if not self.verified:
            return f"nothing verified — {self.reason}"
        return f"{len(self.verified)} file(s) match {XAHAUD_COMMIT[:8]}"


def verify_vendored(xahaud_root: Path | str | None = None) -> VendorCheck:
    """Cross-check the vendored copies against the pin, via `git show`.

    The vendored tree is the reference every citation resolves against, which
    makes "is it honest?" worth asking of something other than itself. A file
    vendored from the wrong commit, or edited afterwards, would otherwise let
    every check pass while the port describes code that never existed.

    Empty when the checkout cannot supply the pin — nothing was verified, and
    nothing is claimed.
    """
    if xahaud_root is None:
        try:
            from hookz.config import load_config
            xahaud_root = load_config().xahaud_root
        except Exception as exc:                           # noqa: BLE001
            return VendorCheck(reason=f"no configured checkout ({exc})")
    if xahaud_root is None or not Path(xahaud_root).exists():
        return VendorCheck(reason=f"checkout {xahaud_root} does not exist")

    vendored = vendored_root()
    # The config falls back to the vendored tree when no checkout resolves.
    # That tree lives inside hookz's own repository, so `git show` there
    # answers about hookz, not xahaud — and every file would "verify" against
    # itself. Refuse rather than self-certify.
    if Path(xahaud_root).resolve() == vendored.resolve():
        return VendorCheck(
            reason="configured checkout is hookz's own vendored tree, which "
                   "cannot verify itself")

    verified: list[str] = []
    problems: list[str] = []
    for rel in PORTED_FILES + CITED_FILES:
        theirs = file_at_pin(xahaud_root, rel)
        if theirs is None:
            continue                    # checkout lacks the pin; say nothing
        ours_path = vendored / rel
        if not ours_path.exists():
            problems.append(f"{rel}: declared but not vendored")
        elif ours_path.read_text(errors="replace") != theirs:
            problems.append(
                f"{rel}: vendored copy differs from {XAHAUD_COMMIT[:8]} — "
                "re-vendor, or the citations into it are describing "
                "something that is not upstream")
        else:
            verified.append(rel)
    if not verified and not problems:
        return VendorCheck(
            reason=f"{xahaud_root} does not contain {XAHAUD_COMMIT[:8]}")
    return VendorCheck(verified=tuple(verified), problems=tuple(problems))


def check_checkout(config=None) -> list[str]:
    """Is the configured xahaud checkout where the config says it is?

    Declaring `paths.xahaud_commit` is optional, and the choice is meaningful:

    * **Omitted** — the checkout is whatever the developer has open. Citations
      are checked against the vendored tree, and any difference upstream is
      reported as advisory `drift:`, useful as early warning before a re-pin.
    * **Declared** — the config asserts the checkout is at a known commit, so a
      mismatch is an error rather than a fact of life. This is what makes a
      build reproducible: the same source, the same headers, the same lines
      behind every citation.

    Declaring the commit hookz itself was ported against (`XAHAUD_COMMIT`) is
    the strictest setting, and the one where citation drift should be empty.
    """
    if config is None:
        from hookz.config import load_config
        config = load_config()
    if not config.xahaud_pinned:
        return []
    root = config.xahaud_root
    actual = checkout_commit(root)
    if actual is None:
        return [f"paths.xahaud_commit is declared but {root} is not a git checkout"]
    # Resolve what the config names rather than comparing strings: a short
    # hash, a tag or a branch all name a commit perfectly well, and rejecting
    # `bb244ef77295` for not equalling `bb244ef7729503a0…` is a wrong answer
    # to a question nobody asked.
    declared = resolve_commit(root, config.xahaud_commit)
    if declared is None:
        return [f"paths.xahaud_commit {config.xahaud_commit!r} does not name a "
                f"commit in {root}"]
    if actual != declared:
        return [f"{root} is at {actual[:12]}, but paths.xahaud_commit declares "
                f"{config.xahaud_commit} ({declared[:12]})"]
    return []


def resolve_commit(root: Path | str, rev: str) -> str | None:
    """The full SHA a revision names in a checkout, or None if it names none."""
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", f"{rev}^{{commit}}"],
                             capture_output=True, text=True, timeout=10)
    except Exception:                                      # noqa: BLE001
        return None
    return out.stdout.strip() or None if out.returncode == 0 else None


def check_citations(root: Path | str,
                    xahaud_root: Path | str | None = None,
                    compare_upstream: bool = False) -> list[str]:
    """Verify every citation under `root` points where it claims.

    Two questions, and they are not the same one:

    **Against the vendored tree** — is the claim true at the commit the port
    was made against? A citation naming a file hookz does not ship, or a line
    past its end, is broken now. These are errors.

    **Against a checkout's working tree** (`compare_upstream=True`) — has the
    line moved *since* the pin? Off by default, and deliberately: a checkout
    sits wherever its owner left it, so comparing against HEAD reports drift
    that means nothing and trains people to ignore the check. Ask for it when
    you are considering a re-pin, which is the only time the answer is
    actionable. Reported as `drift:` unless `paths.xahaud_commit` declared
    where the checkout should be, in which case it is an error.

    For "is the vendored copy honest?", see `verify_vendored`, which reads the
    pin out of a checkout with `git show` rather than trusting its working
    tree.
    """
    root = Path(root)
    vendored = vendored_root()

    upstream: Path | None = None
    # A declared paths.xahaud_commit turns "the checkout has moved" from a fact
    # of life into a broken promise, so the same difference is reported as an
    # error rather than as advisory drift.
    severity = "drift: "
    if compare_upstream:
        if xahaud_root is None:
            try:
                from hookz.config import load_config
                config = load_config()
                xahaud_root = config.xahaud_root
                if config.xahaud_pinned:
                    severity = ""
            except Exception:                              # noqa: BLE001
                xahaud_root = None
        if xahaud_root is not None and Path(xahaud_root).exists():
            upstream = Path(xahaud_root)

    problems: list[str] = []
    for source in sorted(root.rglob("*.py")):
        if "xahaud_lite" in source.parts:
            continue
        for cit in parse_citations(source.read_text(errors="replace")):
            target = vendored / cit.path
            where = f"{source.relative_to(root)}: {cit}"
            if not target.exists():
                problems.append(f"{where} — {cit.path} is not vendored")
                continue
            ours = _line_of(target, cit.line)
            if ours is None:
                total = len(target.read_text(errors="replace").splitlines())
                problems.append(
                    f"{where} — line {cit.line} is outside {cit.path} ({total} lines)")
                continue
            if upstream is None:
                continue
            theirs_path = upstream / cit.path
            if not theirs_path.exists():
                problems.append(
                    f"{severity}{where} — {cit.path} is absent from {upstream}")
                continue
            theirs = _line_of(theirs_path, cit.line)
            if theirs is None:
                problems.append(
                    f"{severity}{where} — line {cit.line} no longer exists upstream")
            elif theirs.strip() != ours.strip():
                problems.append(
                    f"{severity}{where} — upstream line {cit.line} now reads "
                    f"{theirs.strip()[:60]!r}, vendored has {ours.strip()[:60]!r}")
    return problems


def check_drift(xahaud_root: Path | str) -> list[str]:
    """Compare a checkout's ported files against the vendored copies.

    Empty list means the checkout matches what hookz was ported against.
    Drift is not an error — a checkout may legitimately sit on another branch.
    It means the `Guard.h:NNN` citations and the ported behaviour describe
    something other than the files in front of you.
    """
    root = Path(xahaud_root)
    vendored = vendored_root()
    findings = []
    for rel in PORTED_FILES + CITED_FILES:
        theirs, ours = root / rel, vendored / rel
        kind = "ported" if rel in PORTED_FILES else "cited"
        if not theirs.exists():
            findings.append(f"{rel}: missing from {root}")
        elif not ours.exists():
            findings.append(f"{rel}: missing from vendored tree")
        elif sha256(theirs) != sha256(ours):
            findings.append(
                f"{rel} ({kind}): differs from vendored {XAHAUD_COMMIT[:8]}")
    return findings
