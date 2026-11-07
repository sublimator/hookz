"""The reference Xahau C hook compiler, tequdev/hooks-compiler, run at a pin.

Xahau retired the hook-buildbox.xrpl.org service in October 2026. hooks-cli
3.0.0 (Xahau/hooks-cli#61) and the Hooks Builder IDE (Xahau/xrpl-hooks-ide#358)
compile with hooks-compiler instead: clang 22, wasm-ld, binaryen and
hook-cleaner, all as WebAssembly inside Node, deterministic, with no server.

This module runs its CLI through ``npx`` at ``VERSION`` and returns the exact
bytes it wrote. It never falls back to the local pipelines in
``hookz.wasm.pipeline``: those are hookz's own builds and are not byte-identical
to this one.

What is sent matches the buildbox it replaces: one C file, with hookz audit
annotations stripped, plus the configured hook headers (``-I``). Other files
beside the source are not visible to it.
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
from typing import Callable

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


def headers_digest(headers: Path | None) -> str:
    """sha256 over every file hooks-compiler reads under ``-I``.

    It loads the whole tree, keyed by relative path, so any of those files can
    change the output. Symlinked files count; symlinked directories are not
    walked, as in hooks-compiler's own walk.
    """
    h = hashlib.sha256()
    if headers is not None and Path(headers).is_dir():
        root = Path(headers)
        for path in sorted(root.rglob("*")):
            if path.is_file():
                for part in (path.relative_to(root).as_posix().encode(),
                             path.read_bytes()):
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
    headers: Path | None = None,
    npx: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> HooksCompilerResult:
    """Compile one C hook with the pinned hooks-compiler."""
    text, source_sha256 = stripped_source(source)
    name = safe_filename(filename)
    with tempfile.TemporaryDirectory(prefix="hookz-hooks-compiler-") as tmp:
        src = Path(tmp) / "src" / name
        src.parent.mkdir()
        src.write_text(text, encoding="utf-8")
        out = Path(tmp) / "hook.wasm"
        argv = [_npx(npx), "--yes", SPEC, "build", str(src),
                "-o", str(out), "--json"]
        if headers is not None and Path(headers).is_dir():
            argv += ["-I", str(headers)]
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
