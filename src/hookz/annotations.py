"""Strip audit annotations back out of a hook, restoring its original lines.

Hooks report which branch they took by compiling `__LINE__` into the binary —
`accept(SBUF(msg), __LINE__)` for the exit code, `_g(__LINE__, n)` for the
guard id. Those constants are part of the artifact. Add a comment above them
and the binary changes: same logic, same size, different bytes, different
HookHash, different codes on chain.

That is a problem for auditing, because reading a hook properly means writing
on it — state declarations, notes, `hookz:` checkpoint directives — and none of
that should change what you are looking at.

So annotations follow a convention that makes them mechanically removable, and
`strip()` removes them. Compile the stripped source and you get the deployable
binary; read the annotated source and you get the reasoning. `verify()` proves
the two are the same file, which is the part that matters: a strip you cannot
check is a strip you cannot trust.

THE CONVENTION
--------------
An annotation is one of:

    //@@ anything                  a line comment, declaration or prose
    //@@                           a blank separator

    /*@@ ... */                    a block, over any number of lines
    /* hookz: ... */               a dev-directive block (see dev_directives)

Nothing else may be added. A note written as a plain `/* ... */` is
indistinguishable from the author's own comments, so it survives stripping,
shifts every line below it, and silently changes the binary — which is exactly
the failure this module exists to prevent. `verify()` catches it.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

# a whole line that is nothing but an annotation
LINE = re.compile(r"^[ \t]*//@@")

# opens a strippable block comment: /*@@ … */ or the dev-directive /* hookz: … */
BLOCK_OPEN = re.compile(r"^[ \t]*/\*[ \t]*(?:@@|hookz:)")

# a block that opens and closes on one line
BLOCK_ONE_LINE = re.compile(r"^[ \t]*/\*[ \t]*(?:@@|hookz:).*\*/[ \t]*$")


def strip(source: str) -> str:
    """Remove every annotation, leaving the source it was written onto.

    Line-for-line: an annotation contributes nothing, so what remains keeps the
    numbering it had before anyone annotated the file — which is the whole
    point, since those numbers are compiled in.
    """
    out: list[str] = []
    lines = source.splitlines(keepends=True)
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if BLOCK_ONE_LINE.match(line):
            i += 1
            continue
        if BLOCK_OPEN.match(line):
            # C block comments do not nest, so the next `*/` closes it
            while i < n and "*/" not in lines[i]:
                i += 1
            i += 1  # the closing line itself
            continue
        if LINE.match(line):
            i += 1
            continue
        out.append(line)
        i += 1
    return "".join(out)


def line_map(annotated: str) -> dict[int, int]:
    """Annotated line number -> the line it is in the stripped source.

    Hooks compile `__LINE__` into the binary, so a rollback code observed on
    chain is a line number in the *published* file. Coverage, `hookz wce` and
    every finding cite the *annotated* file, because that is the one with the
    reasoning written on it. On a heavily annotated hook those differ by
    hundreds of lines, and nothing
    about either number says which file it belongs to — so looking an on-chain
    code up in the annotated source lands on unrelated code and reads as an
    answer.

    Annotation lines map to None's absence: they are simply not in the result.
    """
    out: dict[int, int] = {}
    published = 0
    lines = annotated.splitlines(keepends=True)
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if BLOCK_ONE_LINE.match(line) or LINE.match(line):
            i += 1
            continue
        if BLOCK_OPEN.match(line):
            while i < n and "*/" not in lines[i]:
                i += 1
            i += 1
            continue
        published += 1
        out[i + 1] = published
        i += 1
    return out


def published_line(annotated: str, line: int) -> int | None:
    """Where an annotated line lands in the published file, or None if it is
    an annotation and has no counterpart."""
    return line_map(annotated).get(line)


def annotated_line(annotated: str, line: int) -> int | None:
    """The reverse: a line number from a deployed binary — a rollback code, a
    guard id — located in the annotated source."""
    for a, p in line_map(annotated).items():
        if p == line:
            return a
    return None


def verify(annotated: str, reference: str) -> list[str]:
    """Differences between the stripped source and what it claims to annotate.

    Empty means the annotated file is provably the reference file plus
    annotations, so the two compile to the same binary. Anything else names a
    line that will move `__LINE__` and change the artifact.
    """
    got = strip(annotated).splitlines()
    want = reference.splitlines()
    if got == want:
        return []
    problems: list[str] = []
    sm = difflib.SequenceMatcher(None, want, got, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        for line in got[j1:j2]:
            problems.append(
                f"line {j1 + 1}: not in the reference and not an annotation: "
                f"{line.strip()[:72]!r}")
        for line in want[i1:i2]:
            problems.append(
                f"line {i1 + 1}: in the reference but missing after stripping: "
                f"{line.strip()[:72]!r}")
    return problems


def verify_files(annotated: Path | str, reference: Path | str) -> list[str]:
    """`verify()` over two paths."""
    return verify(Path(annotated).read_text(), Path(reference).read_text())
