"""Compile C hooks to WASM — wraps wasi-sdk clang."""

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
    """Compile a C hook source to WASM.

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
