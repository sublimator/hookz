"""Centralized config — reads hookz.toml with env var overrides.

Any [paths] key is overridable by HOOKZ_<KEY> env var (uppercased).
Any value can reference other paths via ${name} substitution.
Resolution order: env var > hookz.toml > empty.

Example hookz.toml:
    [paths]
    xahaud = "../xahaud"
    tipbot = "../tipbot-hooks"
    hook_headers = "${xahaud}/hook"

    [hooks]
    tip = "${tipbot}/tip.c"

Override: HOOKZ_TIPBOT=/other/path hookz test
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HookzConfig:
    paths: dict[str, Path] = field(default_factory=dict)
    hooks: dict[str, Path] | None = None
    compile_target: str = "wasm32-wasip1"
    extra_cflags: list[str] | None = None
    exports: list[str] | None = None
    coverage_threshold: int = 90

    # Convenience accessors for common paths
    @property
    def xahaud_root(self) -> Path:
        return self.paths.get("xahaud", Path())

    @property
    def wasi_sdk(self) -> Path:
        return self.paths.get("wasi_sdk", Path())

    @property
    def hook_headers(self) -> Path:
        return self.paths.get("hook_headers", Path())


def _find_toml(start: Path | None = None) -> Path | None:
    """Walk up from start (default CWD) looking for hookz.toml."""
    p = start or Path.cwd()
    for d in [p, *p.parents]:
        candidate = d / "hookz.toml"
        if candidate.exists():
            return candidate
    return None


def _substitute(raw: str, variables: dict[str, str]) -> str:
    """Replace ${name} references with resolved values."""
    def replacer(m):
        key = m.group(1)
        return variables.get(key, m.group(0))
    return re.sub(r'\$\{(\w+)\}', replacer, raw)


def _resolve_path(raw: str, base: Path, variables: dict[str, str]) -> Path:
    """Resolve a path: substitute ${var}, expand ~, make relative to base."""
    raw = _substitute(raw, variables)
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = base / p
    return p.resolve()


def load_config(toml_path: Path | None = None) -> HookzConfig:
    """Load config from hookz.toml with env var overrides."""
    if toml_path is None:
        toml_path = _find_toml()

    toml_data: dict = {}
    base = Path.cwd()
    if toml_path and toml_path.exists():
        with open(toml_path, "rb") as f:
            toml_data = tomllib.load(f)
        base = toml_path.parent

        # Merge .hookz.local.toml overrides (same dir, not committed)
        local_path = toml_path.parent / ".hookz.local.toml"
        if local_path.exists():
            with open(local_path, "rb") as f:
                local_data = tomllib.load(f)
            for section, values in local_data.items():
                if isinstance(values, dict):
                    toml_data.setdefault(section, {}).update(values)
                else:
                    toml_data[section] = values

    paths_cfg = toml_data.get("paths", {})
    compile_cfg = toml_data.get("compile", {})
    coverage_cfg = toml_data.get("coverage", {})
    hooks_cfg = toml_data.get("hooks", {})

    # Default hook_headers to ${xahaud}/hook if xahaud is set
    if "xahaud" in paths_cfg and "hook_headers" not in paths_cfg:
        paths_cfg["hook_headers"] = "${xahaud}/hook"

    # Resolve [paths] in dependency order — multiple passes to handle
    # forward references like hook_headers = "${xahaud}/hook"
    resolved: dict[str, str] = {}
    for _pass in range(3):
        for key, raw in paths_cfg.items():
            env_key = f"HOOKZ_{key.upper()}"
            raw = os.environ.get(env_key, raw)
            resolved[key] = str(_resolve_path(raw, base, resolved))

    paths = {k: Path(v) for k, v in resolved.items()}

    # Resolve [hooks] with all paths available as variables
    hooks = None
    if hooks_cfg:
        hooks = {}
        for name, source in hooks_cfg.items():
            hooks[name] = _resolve_path(source, base, resolved)

    return HookzConfig(
        paths=paths,
        hooks=hooks,
        compile_target=compile_cfg.get("target", "wasm32-wasip1"),
        extra_cflags=compile_cfg.get("extra_cflags"),
        exports=compile_cfg.get("exports", ["hook", "cbak"]),
        coverage_threshold=coverage_cfg.get("threshold", 90),
    )
