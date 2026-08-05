"""Provenance pin for the external-env-tests branch.

Separate from `wasm/xahaud_ref.py` on purpose, and the reason is written into
that module: it pins the revision hookz's guard checker was *ported from*, and
says in as many words not to re-pin it to a feature branch, because a branch
carries unmerged patches and porting against one bakes non-network behaviour
into hookz.

This pins the opposite kind of thing. `external-env-tests` is a branch that is
deliberately not on dev — it turns xahaud into a test runner for external hook
projects, which upstream has no reason to carry. It has its own tip, its own
lifetime, and it moves when dev is merged into it, on a schedule unrelated to
the port pin. One registry tracking both would have to be re-pinned for two
different reasons and could not say which had happened.

What hookz ships is not the branch but its diff against dev
(`patches/xahaud-external-env-tests.patch`), so what can be pinned is the
patch: its content hash, the files it touches, and what each one is for.
`hookz env-test-context` inlines the pieces of it an agent needs.

PIN
---
Repo    https://github.com/Xahau/xahaud
Branch  external-env-tests @ 10b901ea0b17a89fc3279e70c661bd91dc3d21ef (2026-07-30)
Base    generated as `git diff origin/dev external-env-tests`, so it applies
        to a current dev checkout rather than to a fixed commit
Patch   sha256 9241a45b1ee8445db2ec63b0645cbc903b9d23c9ae4d5d4e15e415b31d563eee

The commit is recorded on direct evidence rather than on the dates lining up:
`TestEnv.h` reconstructed from this patch is byte-identical to that commit's
copy, and `TestEnv.h` is the one file the patch adds outright, so it carries
no context lines that could mask a difference. `check_pin()` re-checks the
hash; `check_branch()` checks a given checkout against it.

REGENERATING
------------
    git -C <xahaud> diff origin/dev external-env-tests \\
        > patches/xahaud-external-env-tests.patch

then update PATCH_SHA256 and BRANCH_COMMIT here. `test_env_tests_ref.py` fails
until you do, which is the point: a patch nobody can identify is worse than a
stale one nobody has noticed, because it still looks authoritative.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

REPO = "https://github.com/Xahau/xahaud"
BRANCH = "external-env-tests"
BRANCH_COMMIT = "10b901ea0b17a89fc3279e70c661bd91dc3d21ef"
BRANCH_COMMIT_DATE = "2026-07-30"
BASE_REF = "origin/dev"

PATCH_NAME = "xahaud-external-env-tests.patch"
PATCH_SHA256 = "9241a45b1ee8445db2ec63b0645cbc903b9d23c9ae4d5d4e15e415b31d563eee"

# The file the branch adds outright. Its diff is the file, so it can be handed
# to a reader as C++ rather than as a diff — which is what a test author
# actually needs, since it is the class their test constructs.
HARNESS_HEADER = "src/test/jtx/TestEnv.h"

# Every file the patch touches, and why. Kept total against the patch by
# `test_the_registry_describes_every_file_in_the_patch`: a file appearing in a
# regenerated patch with no entry here fails, rather than being inlined with
# no explanation of what it is for.
#
# The descriptions themselves are NOT machine-checked, and cannot easily be:
# they are prose about C++ hunks. Nothing here stops one being wrong, so the
# bar is that each was read against its hunk in the patch and against the
# branch checkout before being written. Three of the first twelve were wrong
# in the same direction — naming a plausible neighbour rather than the thing
# that changed (`DEFINE_HOOK_FUNCTION` for `HOOK_SETUP`, `Env` twice for
# `Logs*`) — and a reader working from this manifest instead of the diff has
# no way to notice. If you edit one, open the hunk.
FILES: dict[str, str] = {
    "cmake/RippledCore.cmake":
        "finds your *_test.cpp via HOOKS_TEST_DIR, runs `hookz "
        "build-test-hooks` per file, and adds the HOOKS_* options",
    "include/xrpl/basics/Log.h":
        "Logs::setTransform, so TestEnv can rewrite r-addresses to "
        "Account(name) across all output",
    "include/xrpl/hook/Enum.h":
        "adds __on_source_line to the import whitelist with a void_t return",
    "include/xrpl/hook/Guard.h":
        "consults the whitelist for void returns instead of requiring every "
        "import to return exactly one value",
    "include/xrpl/hook/Macro.h":
        "adds `jh`, the HooksTrace journal, to the HOOK_SETUP() macro "
        "(Macro.h:160) — not to DEFINE_HOOK_FUNCTION, which does not "
        "expand it; every API implementation calls HOOK_SETUP itself",
    "src/libxrpl/basics/Log.cpp":
        "applies the transform on the write path",
    "src/test/jtx/Env.h":
        "SuiteLogs::makeSink passes `this` — a Logs*, not an Env — to "
        "SuiteJournalSink, so the suite journal gets the transform too",
    "src/test/jtx/TestEnv.h":
        "the harness itself — named accounts, the log transform, setPrefix, "
        "and TESTENV_LOGGING",
    "src/test/unit_test/SuiteJournal.h":
        "SuiteJournalSink takes a `Logs* logs = nullptr` and writes "
        "logs_->applyTransform(text) when it is set",
    "src/xrpld/app/hook/applyHook.h":
        "coverage: onSourceLine, coverageMap, coverageDump, coverageLabel, "
        "coverageReset",
    "src/xrpld/app/hook/detail/applyHook.cpp":
        "switches the trace APIs from the View journal `j` to `jh` and wraps "
        "them in JLOG; `jh` itself comes from HOOK_SETUP in Macro.h",
    "src/xrpld/app/tx/detail/SetHook.cpp":
        "comment-only change on the validateGuards call",
}


# The sha256 of each file's own section of the diff, at the pinned commit.
#
# Descriptions cannot be machine-checked for correctness, but they can be
# bound to the hunk they were read against. When the patch is regenerated
# these say which three moved rather than declaring all twelve unverified —
# so the review that follows a dev merge is proportionate to what changed,
# instead of a hash bump nobody scrutinises. Regenerate with:
#
#   python -c "from hookz.env_tests_ref import file_digests; print(file_digests())"
FILE_DIGESTS: dict[str, str] = {
    'cmake/RippledCore.cmake':
        'f7e869ea65ee23bedd42525f6d4d261d4360d76c19ea12775949d3a35bba2417',
    'include/xrpl/basics/Log.h':
        'd7bbf14263763092f18b19ecd8d22ec0d254fdb7ad15d0f1b454d8fffaa29c75',
    'include/xrpl/hook/Enum.h':
        '721ba50c9e54e9f3cda4cbb6d264e5df5f8717a8a8fd42ad8b68a453c1d7d1e6',
    'include/xrpl/hook/Guard.h':
        'd031abc49ed26b9768e42b77b18d358a829d3d312101c0c18dae027200a6ffdc',
    'include/xrpl/hook/Macro.h':
        '133bc559d987e08ce05e795c4a017ecb3944eded669a2007fdaf6979b6f83889',
    'src/libxrpl/basics/Log.cpp':
        'b924e1482b4d665831470c9352849d8a2b3c7cfd2cc1c2ad9190db474080b142',
    'src/test/jtx/Env.h':
        '93c52badf4dd7a88b3c2aa7c11ce07264f55a46f2a9ac9d0aceda10411b8f010',
    'src/test/jtx/TestEnv.h':
        '83a6868997897414a2c7e516202eceed92110d1d51555a7ad264a08344c81038',
    'src/test/unit_test/SuiteJournal.h':
        'ab554de027f83254feed7672e8dd9ff4a0ddf1f44891a7a809c5cb83c483deb8',
    'src/xrpld/app/hook/applyHook.h':
        'b20067331fc8c1c997880a5fe57a68f4e615cdff24b2654a9443e48102e71d90',
    'src/xrpld/app/hook/detail/applyHook.cpp':
        'b5e82fc6f5d36b625a03983dffce375ab362a4905ae7c3d8150940a991764ad6',
    'src/xrpld/app/tx/detail/SetHook.cpp':
        '4e15c9cab42df2c502c94e3bba477c577ae7ff2eb320faf31459846771b7ea6f',
}


def patch_path() -> Path:
    """The vendored patch, installed or in a checkout.

    `patches/` sits outside `src/hookz`, so a wheel gets it only through the
    force-include in pyproject, and only under `hookz/data/`. A source
    checkout has no packaged copy and falls through to the repo path — which
    is also where the regeneration command writes, so a developer who
    regenerates it sees the new one immediately.
    """
    packaged = Path(__file__).resolve().parent / "data" / PATCH_NAME
    if packaged.is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "patches" / PATCH_NAME


def patch_text() -> str:
    return patch_path().read_text(errors="replace")


def files_in_patch(text: str | None = None) -> list[tuple[str, int, int, bool]]:
    """(path, added, removed, is_new) per file, in the order the diff has them."""
    text = patch_text() if text is None else text
    rows: list[tuple[str, int, int, bool]] = []
    path, added, removed, is_new = None, 0, 0, False
    for line in text.splitlines():
        if line.startswith("diff --git"):
            if path is not None:
                rows.append((path, added, removed, is_new))
            path, added, removed, is_new = line.split(" b/")[-1], 0, 0, False
        elif line.startswith("--- /dev/null"):
            is_new = True
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    if path is not None:
        rows.append((path, added, removed, is_new))
    return rows


def file_digests(text: str | None = None) -> dict[str, str]:
    """sha256 of each file's own section of the diff.

    PATCH_SHA256 fires on any regeneration, as one undifferentiated "this was
    regenerated". That is the wrong granularity for the thing most likely to
    go wrong: when dev is merged and the patch is rebuilt, the honest state is
    "all twelve descriptions are now unverified", and the practical outcome is
    that someone bumps the hash and moves on.

    Per-file digests turn that into "these three hunks moved, re-read their
    descriptions; the other nine are unchanged and carry forward with
    evidence". It does not check that a description is *correct* — nothing
    mechanical can, see the note above FILES — but it does say exactly which
    ones stopped being backed by a hunk anyone has read.
    """
    text = patch_text() if text is None else text
    out: dict[str, str] = {}
    path, buf = None, []
    for line in text.splitlines(keepends=True):
        if line.startswith("diff --git"):
            if path is not None:
                out[path] = hashlib.sha256("".join(buf).encode()).hexdigest()
            path, buf = line.split(" b/")[-1].strip(), []
        elif path is not None:
            buf.append(line)
    if path is not None:
        out[path] = hashlib.sha256("".join(buf).encode()).hexdigest()
    return out


def new_file(rel_path: str, text: str | None = None) -> str | None:
    """The content of a file the patch adds outright, as the file itself.

    Only meaningful for an added file: every line of its hunk is an addition,
    so stripping the `+` reconstructs it exactly. For a modified file the
    result would be the added lines with the surrounding code missing, which
    reads like source and is not, so this returns None for those rather than
    producing something plausible.
    """
    text = patch_text() if text is None else text
    out: list[str] = []
    on = is_new = False
    for line in text.splitlines():
        if line.startswith("diff --git"):
            if on:
                break
            on = f" b/{rel_path}" in line
            continue
        if not on:
            continue
        # `--- /dev/null` is the only sound test for "added outright".
        # "has no removed lines" is not: RippledCore.cmake is +114 -0, and
        # keying on that reconstructed 114 added lines as if they were the
        # whole file.
        if line.startswith("--- /dev/null"):
            is_new = True
            continue
        if line.startswith(("index ", "new file", "--- ", "+++ ", "@@")):
            continue
        if line.startswith("+"):
            out.append(line[1:])
    if not out or not is_new:
        return None
    return "\n".join(out) + "\n"


def check_pin() -> list[str]:
    """Ways the vendored patch differs from what this module claims."""
    findings = []
    path = patch_path()
    if not path.is_file():
        return [f"the vendored patch is missing: {path}"]

    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != PATCH_SHA256:
        findings.append(
            f"{path} has sha256 {actual[:12]}…, pinned as {PATCH_SHA256[:12]}… "
            "— regenerated without updating env_tests_ref.py")

    described = set(FILES)
    present = {p for p, _, _, _ in files_in_patch()}
    for missing in sorted(present - described):
        findings.append(f"{missing} is in the patch with no entry in FILES")
    for gone in sorted(described - present):
        findings.append(f"{gone} is described in FILES but not in the patch")

    for path, digest in sorted(file_digests().items()):
        pinned = FILE_DIGESTS.get(path)
        if pinned is not None and pinned != digest:
            findings.append(
                f"{path}: its hunk changed, so the FILES description for it "
                "is no longer backed by anything anyone has read — re-read "
                "the hunk and update env_tests_ref.py")
    return findings


def check_branch(root: Path | str) -> list[str]:
    """Ways a checkout differs from the pinned branch, for what hookz reads.

    Only the harness header, because it is the only file the patch adds and so
    the only one that can be compared without applying anything. A modified
    file matching or not is a question about a three-way merge, which this
    deliberately does not pretend to answer.
    """
    header = Path(root) / HARNESS_HEADER
    if not header.is_file():
        return [f"{HARNESS_HEADER} is absent — this checkout does not carry "
                f"the {BRANCH} branch"]

    pinned = new_file(HARNESS_HEADER)
    if pinned is None:
        return [f"{HARNESS_HEADER} could not be reconstructed from the patch"]
    if header.read_text(errors="replace") != pinned:
        return [f"{HARNESS_HEADER} differs from the pinned {BRANCH} copy "
                f"({BRANCH_COMMIT[:8]}) — the checkout is ahead, behind, or "
                "carries local changes"]
    return []
