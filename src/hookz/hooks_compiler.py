"""The reference Xahau C hook compiler, tequdev/hooks-compiler, run at a pin.

Xahau retired the hook-buildbox.xrpl.org service in October 2026. hooks-cli
3.0.0 (Xahau/hooks-cli#61) and the Hooks Builder IDE (Xahau/xrpl-hooks-ide#358)
compile with hooks-compiler instead: clang 22, wasm-ld, binaryen and
hook-cleaner, all as WebAssembly inside Node, deterministic, with no server.

This module runs its CLI through ``npx`` at ``VERSION`` and returns the exact
bytes it wrote. It never falls back to the local pipelines in
``hookz.wasm.pipeline``: those are hookz's own builds and are not byte-identical
to this one.

It is given the C file with hookz audit annotations stripped, and the
headers a local build can reach: those under the source's own directory, the
project's ``extra_cflags`` ``-I`` directories, and the hook headers.

hooks-compiler does not search directories the way clang does. It merges
every file it is given into one tree, keyed by relative path, and the first
file for a name wins. So a name that two of those directories supply with
different contents could resolve to a different header than clang would pick.
hookz stages that tree itself and refuses such a name rather than guess.
Every layout it accepts gives each relative path exactly one meaning.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from hookz.annotations import strip as strip_annotations

PACKAGE = "hooks-compiler"
VERSION = "0.2.0"
SPEC = f"{PACKAGE}@{VERSION}"
NODE_REQUIREMENT = ">= 20.12"
# The first run downloads the toolchain (~30 MB, plus binaryen) into npm's
# cache; a warm compile takes a few seconds.
DEFAULT_TIMEOUT = 600.0
WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"

_SAFE_NAME = re.compile(r"[A-Za-z0-9_-]+\.c")


class HooksCompilerError(RuntimeError):
    """hooks-compiler produced no usable artifact."""


@dataclass(frozen=True)
class HooksCompilerResult:
    """The artifact plus enough provenance to identify how it was made."""

    wasm: bytes
    compiler: str
    source_sha256: str
    wasm_sha256: str
    filename: str
    imports: tuple[str, ...]
    exports: tuple[str, ...]
    raw_size: int
    optimized_size: int


def safe_filename(filename: str) -> str:
    """The entry name hooks-compiler is given: the source's own if it is a
    plain ``name.c``, else ``hook.c``. It decides C vs C++ by extension and
    keys files by basename, so nothing else is passed through."""
    name = Path(filename).name
    return name if _SAFE_NAME.fullmatch(name) else "hook.c"


def stripped_source(source: str) -> tuple[str, str]:
    """The text that is compiled, and its sha256.

    Annotations are removed here rather than by callers, so ``build``,
    ``wce`` and ``build-test-hooks`` cannot disagree about the source.
    """
    stripped = strip_annotations(source)
    return stripped, hashlib.sha256(stripped.encode("utf-8")).hexdigest()


def include_dirs(config) -> list[Path]:
    """The ``-I`` directories a local build of this project uses, in clang's
    order: the ``-I`` entries of ``extra_cflags``, then the hook headers.
    Relative entries resolve against the working directory, as clang's do."""
    flags = list(getattr(config, "extra_cflags", None) or [])
    dirs: list[Path] = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag == "-I" and i + 1 < len(flags):
            dirs.append(Path(flags[i + 1]))
            i += 2
            continue
        if flag.startswith("-I") and len(flag) > 2:
            dirs.append(Path(flag[2:]))
        i += 1
    dirs = [d.expanduser().resolve() for d in dirs]
    headers = getattr(config, "hook_headers", None)
    if headers is not None:
        dirs.append(Path(headers))
    return dirs


def _headers_under(root: Path):
    """``(relative path, file)`` for every ``.h`` under root, skipping hidden
    directories. Symlinked files count; symlinked directories are not walked."""
    for path in sorted(root.rglob("*.h")):
        rel = path.relative_to(root)
        if any(part.startswith(".") for part in rel.parts[:-1]):
            continue
        if path.is_file():
            yield rel.as_posix(), path


def stage_headers(roots: Sequence[Path], dest: Path) -> int:
    """Merge the headers under ``roots`` into one tree at ``dest``, the shape
    hooks-compiler compiles against. Returns how many files were staged.

    A relative path that two roots supply with different bytes is refused:
    hooks-compiler would take one of them, and clang, which searches the
    including file's directory and then each ``-I`` in turn, might take the
    other. Identical copies are not a conflict.
    """
    seen: dict[str, tuple[Path, bytes]] = {}
    clashes: list[str] = []
    for root in (Path(r) for r in roots):
        if not root.is_dir():
            continue
        for key, path in _headers_under(root):
            data = path.read_bytes()
            if key in seen:
                if seen[key][1] != data:
                    clashes.append(f"  {key}: {seen[key][0]} and {path}")
                continue
            seen[key] = (path, data)
            target = dest / key
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    if clashes:
        raise HooksCompilerError(
            "hooks-compiler merges every include directory into one tree, so "
            "these names could resolve to a different header than clang "
            "would pick. Rename one copy or drop one include directory:\n"
            + "\n".join(clashes)
        )
    return len(seen)


def headers_digest(roots: Sequence[Path]) -> str:
    """sha256 over the headers ``stage_headers`` would stage from ``roots``."""
    h = hashlib.sha256()
    for index, root in enumerate(Path(r) for r in roots):
        if not root.is_dir():
            continue
        h.update(f"root {index}".encode())
        for key, path in _headers_under(root):
            for part in (key.encode(), path.read_bytes()):
                h.update(len(part).to_bytes(8, "big"))
                h.update(part)
    return h.hexdigest()


def cache_identity(filename: str, headers_sha256: str) -> str:
    """Everything besides the source text that decides the output: the pinned
    version, the entry name it is compiled under, and the header tree."""
    return f"{SPEC}|{safe_filename(filename)}|{headers_sha256}"


def _npx(npx: str | None) -> str:
    found = npx or shutil.which("npx")
    if not found:
        raise HooksCompilerError(
            f"--hooks-compiler runs {SPEC} through npx: install Node "
            f"{NODE_REQUIREMENT} (npx comes with it) and put it on PATH"
        )
    return found


def _run(run, argv: list[str], timeout: float, cwd: str | None = None):
    try:
        return run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    except FileNotFoundError as exc:
        raise HooksCompilerError(f"could not run {argv[0]}: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HooksCompilerError(
            f"{SPEC} did not finish within {timeout:.0f}s"
        ) from exc


def _tail(text: str, limit: int = 8000) -> str:
    text = (text or "").strip()
    return text[-limit:] if text else "(no output)"


def ensure_available(
    *,
    npx: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> None:
    """Fetch the pinned package once, before any parallel compiles.

    Concurrent first runs of ``npx`` would each download into the same cache.
    """
    proc = _run(run, [_npx(npx), "--yes", SPEC, "--help"], timeout)
    if proc.returncode != 0:
        raise HooksCompilerError(
            f"{SPEC} is not runnable (exit {proc.returncode}):\n"
            f"{_tail(proc.stderr or proc.stdout)}"
        )


def compile_source(
    source: str,
    *,
    filename: str = "hook.c",
    include_dirs: Sequence[Path] = (),
    source_dir: Path | None = None,
    npx: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> HooksCompilerResult:
    """Compile one C hook with the pinned hooks-compiler.

    The headers under ``source_dir`` (the hook's own directory, so nested
    ``sub/x.h`` includes resolve too) and under each of ``include_dirs`` are
    staged into one tree by ``stage_headers``, which refuses ambiguous names.
    """
    text, source_sha256 = stripped_source(source)
    name = safe_filename(filename)
    with tempfile.TemporaryDirectory(prefix="hookz-hooks-compiler-") as tmp:
        src = Path(tmp) / "src" / name
        src.parent.mkdir()
        src.write_text(text, encoding="utf-8")
        out = Path(tmp) / "hook.wasm"
        argv = [_npx(npx), "--yes", SPEC, "build", str(src),
                "-o", str(out), "--json"]
        roots = [*([source_dir] if source_dir is not None else []),
                 *include_dirs]
        staged = Path(tmp) / "include"
        if stage_headers(roots, staged):
            argv += ["-I", str(staged)]
        proc = _run(run, argv, timeout, cwd=tmp)
        if proc.returncode != 0:
            raise HooksCompilerError(
                f"{SPEC} failed (exit {proc.returncode}):\n{_tail(proc.stderr)}"
            )
        try:
            report = json.loads(proc.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise HooksCompilerError(
                f"{SPEC} printed no JSON report: {_tail(proc.stdout)}"
            ) from exc
        try:
            wasm = out.read_bytes()
        except OSError as exc:
            raise HooksCompilerError(f"{SPEC} wrote no output: {exc}") from exc

    if not wasm.startswith(WASM_MAGIC):
        raise HooksCompilerError(f"{SPEC} output is not a WebAssembly 1 module")
    digest = hashlib.sha256(wasm).hexdigest()
    if report.get("sha256") != digest:
        raise HooksCompilerError(
            f"{SPEC} reported sha256 {report.get('sha256')} but wrote {digest}"
        )
    return HooksCompilerResult(
        wasm=wasm,
        compiler=SPEC,
        source_sha256=source_sha256,
        wasm_sha256=digest,
        filename=name,
        imports=tuple(report.get("imports", ())),
        exports=tuple(report.get("exports", ())),
        raw_size=int(report.get("rawSize", 0)),
        optimized_size=int(report.get("optimizedSize", 0)),
    )
