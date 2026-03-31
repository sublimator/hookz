"""Compile C hooks to WASM — wraps wasi-sdk clang.

Supports two modes:
- Single-stage: clang driver (may auto-invoke wasm-opt, losing DWARF at -Oz)
- Two-stage: clang -c → .o, then wasm-ld directly (preserves DWARF at -Oz)
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from hookz.config import HookzConfig, load_config


def compile_hook(
    source: Path,
    output: Path | None = None,
    config: HookzConfig | None = None,
    debug: bool = True,
    optimize: bool = False,
) -> bytes:
    """Compile a C hook source to WASM (single-stage, via clang driver).

    Args:
        source: path to .c file
        output: optional output path (otherwise uses temp file)
        config: hookz config (loaded from hookz.toml if None)
        debug: include DWARF debug info (-g)
        optimize: optimization level (-O2 vs -O0)

    Returns:
        WASM bytes
    """
    if config is None:
        config = load_config()

    clang = config.wasi_sdk / "bin" / "clang"
    sysroot = config.wasi_sdk / "share" / "wasi-sysroot"

    if output is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
        tmp.close()
        out_path = Path(tmp.name)
    else:
        out_path = output

    cmd = [
        str(clang),
        f"--target={config.compile_target}",
        f"--sysroot={sysroot}",
        "-nostdlib",
    ]

    if debug:
        cmd.append("-g")
    cmd.append("-O2" if optimize else "-O0")

    # Sensible defaults for hook compilation — the hook API headers
    # trigger these warnings in every hook
    cmd.extend([
        "-Wno-incompatible-pointer-types",
        "-Wno-int-conversion",
        "-Wno-macro-redefined",
    ])

    if config.extra_cflags:
        cmd.extend(config.extra_cflags)

    cmd.extend([
        "-Wl,--allow-undefined",
        "-Wl,--no-entry",
    ])

    for export in (config.exports or ["hook", "cbak"]):
        cmd.append(f"-Wl,--export={export}")

    cmd.extend([
        f"-I{config.hook_headers}",
        "-x", "c",
        str(source),
        "-o", str(out_path),
    ])

    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"Compilation failed:\n{r.stderr.decode()}")

    wasm_bytes = out_path.read_bytes()
    return wasm_bytes


def compile_hook_two_stage(
    source: Path,
    config: HookzConfig | None = None,
    opt_level: str = "-Oz",
) -> bytes:
    """Compile a C hook with two-stage build: clang -c → wasm-ld.

    This bypasses the clang driver's auto-invocation of wasm-opt,
    preserving DWARF line tables on optimized code. Produces a binary
    with accurate source mapping at any optimization level.

    Args:
        source: path to .c file
        config: hookz config
        opt_level: optimization flag (e.g. "-Oz", "-Os", "-O2", "-O0")

    Returns:
        WASM bytes (optimized, with DWARF)
    """
    if config is None:
        config = load_config()

    clang = config.wasi_sdk / "bin" / "clang"
    wasm_ld = config.wasi_sdk / "bin" / "wasm-ld"
    sysroot = config.wasi_sdk / "share" / "wasi-sysroot"

    with tempfile.TemporaryDirectory() as tmpdir:
        obj_path = Path(tmpdir) / "hook.o"
        wasm_path = Path(tmpdir) / "hook.wasm"

        # Stage 1: compile to object file with debug info + optimization
        compile_cmd = [
            str(clang),
            f"--target={config.compile_target}",
            f"--sysroot={sysroot}",
            "-g", opt_level, "-c",
            "-Wno-incompatible-pointer-types",
            "-Wno-int-conversion",
            "-Wno-macro-redefined",
        ]

        if config.extra_cflags:
            compile_cmd.extend(config.extra_cflags)

        compile_cmd.extend([
            f"-I{config.hook_headers}",
            "-x", "c",
            str(source),
            "-o", str(obj_path),
        ])

        r = subprocess.run(compile_cmd, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"Compilation failed:\n{r.stderr.decode()}")

        # Stage 2: link with wasm-ld directly (no wasm-opt auto-invocation)
        link_cmd = [
            str(wasm_ld),
            str(obj_path),
            "--no-entry",
            "--allow-undefined",
        ]

        for export in (config.exports or ["hook", "cbak"]):
            link_cmd.append(f"--export={export}")

        link_cmd.extend([
            "-o", str(wasm_path),
        ])

        r = subprocess.run(link_cmd, capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"Linking failed:\n{r.stderr.decode()}")

        return wasm_path.read_bytes()
