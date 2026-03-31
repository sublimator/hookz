"""wasm-opt wrapper — thin interface to binaryen CLI for hook-specific operations.

Requires wasm-opt to be installed (brew install binaryen).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class WasmOptError(Exception):
    """Raised when wasm-opt fails."""


def _find_wasm_opt() -> str:
    """Find wasm-opt binary."""
    path = shutil.which("wasm-opt")
    if path is None:
        raise WasmOptError(
            "wasm-opt not found. Install with: brew install binaryen")
    return path


def _run_wasm_opt(wasm: bytes, flags: list[str]) -> bytes:
    """Run wasm-opt with given flags on WASM bytes, return result bytes."""
    wasm_opt = _find_wasm_opt()
    with tempfile.NamedTemporaryFile(suffix=".wasm", delete=False) as f_in:
        f_in.write(wasm)
        in_path = f_in.name
    out_path = in_path + ".out"
    try:
        result = subprocess.run(
            [wasm_opt, in_path, "-o", out_path] + flags,
            capture_output=True,
        )
        if result.returncode != 0:
            raise WasmOptError(
                f"wasm-opt failed (exit {result.returncode}): "
                f"{result.stderr.decode(errors='replace')}")
        return Path(out_path).read_bytes()
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


def strip_debug(wasm: bytes) -> bytes:
    """Strip debug info, producers, and target features sections."""
    return _run_wasm_opt(wasm, [
        "--strip-debug",
        "--strip-producers",
        "--strip-target-features",
    ])


def optimize_size(wasm: bytes) -> bytes:
    """Optimize for size — good default for production hooks."""
    return _run_wasm_opt(wasm, ["-Oz"])


def optimize_hook(wasm: bytes) -> bytes:
    """Full hook optimization pipeline matching xahaud genesis makefile.

    Runs in two passes:
    1. Flatten + aggressive optimization
    2. Size optimization
    """
    # Pass 1: flatten then optimize (some passes require flat IR)
    wasm = _run_wasm_opt(wasm, [
        "--flatten",
        "--vacuum",
        "--merge-blocks",
        "--merge-locals",
        "--ignore-implicit-traps",
        "-ffm",
        "--const-hoisting",
        "--code-folding",
        "--code-pushing",
        "--dae-optimizing",
        "--dce",
        "--simplify-globals-optimizing",
        "--simplify-locals-nonesting",
        "--reorder-locals",
        "--precompute-propagate",
        "--local-cse",
        "--remove-unused-brs",
        "--memory-packing",
        "-c",
        "--avoid-reinterprets",
        "-Oz",
    ])
    # Pass 2: coalesce and shrink further
    return _run_wasm_opt(wasm, [
        "--coalesce-locals-learning",
        "--vacuum",
        "--dce",
        "-Oz",
    ])


def remove_unused(wasm: bytes) -> bytes:
    """Remove unused module elements (global DCE)."""
    return _run_wasm_opt(wasm, ["--remove-unused-module-elements"])
