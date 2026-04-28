"""Centralized config — reads hookz.toml with env var overrides.

Any [paths] key is overridable by HOOKZ_<KEY> env var (uppercased).
`paths.xahaud` also accepts HOOKZ_XAHAUD_ROOT for callers that already use
that spelling.
Any value can reference other paths via ${name} substitution.

Config resolution order (later wins):
1. ~/.config/hookz/hookz.toml   — machine-level defaults (wasi_sdk, xahaud)
2. hookz.toml walk up from CWD  — project-level settings
3. hookz.toml walk up from source file — when building someone else's hook
4. .hookz.local.toml next to any found hookz.toml — local overrides
5. HOOKZ_* env vars             — per-invocation overrides
6. Auto-detection               — wasi_sdk from common install locations

Example hookz.toml:
    [paths]
    xahaud = "../xahaud"
    tipbot = "../tipbot-hooks"
    hook_headers = "${xahaud}/hook"

    [hooks]
    tip = "${tipbot}/tip.c"

Override: HOOKZ_XAHAUD=/path/to/xahaud hookz build hook.c
Override: HOOKZ_WASI_SDK=/opt/wasi-sdk hookz build hook.c
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


# Well-known locations for wasi-sdk, checked in order.
_WASI_SDK_SEARCH = [
    # mise (asdf-compatible)
    Path("~/.local/share/mise/installs/wasi-sdk"),
    # Manual install
    Path("/opt/wasi-sdk"),
    Path("~/.local/share/wasi-sdk"),
    # Homebrew (macOS)
    Path("/opt/homebrew/share/wasi-sdk"),
    Path("/usr/local/share/wasi-sdk"),
]


@dataclass
class HookzConfig:
    paths: dict[str, Path] = field(default_factory=dict)
    hooks: dict[str, Path] | None = None
    compile_target: str = "wasm32-wasip1"
    extra_cflags: list[str] | None = None
    exports: list[str] | None = None
    coverage_threshold: int = 90
    # Provenance: maps "section.key" → source description
    sources: dict[str, str] = field(default_factory=dict)

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


class ConfigError(Exception):
    """Raised when required config is missing."""


def _find_toml(start: Path | None = None) -> Path | None:
    """Walk up from start (default CWD) looking for hookz.toml."""
    p = (start or Path.cwd()).resolve()
    for d in [p, *p.parents]:
        candidate = d / "hookz.toml"
        if candidate.exists():
            return candidate
    return None


def _global_config_path() -> Path:
    """~/.config/hookz/hookz.toml"""
    return Path("~/.config/hookz/hookz.toml").expanduser()


def _detect_wasi_sdk() -> Path | None:
    """Try to find wasi-sdk from env var or common install locations."""
    # 1. WASI_SDK_PATH env var (standard convention)
    env_path = os.environ.get("WASI_SDK_PATH")
    if env_path:
        p = Path(env_path).expanduser()
        if (p / "bin" / "clang").exists():
            return p

    # 2. Search well-known locations
    for base in _WASI_SDK_SEARCH:
        base = base.expanduser()
        if not base.exists():
            continue
        # Direct hit (e.g. /opt/wasi-sdk/bin/clang)
        if (base / "bin" / "clang").exists():
            return base
        # Versioned subdirs (e.g. mise: ~/.local/share/mise/installs/wasi-sdk/32/wasi-sdk)
        if base.is_dir():
            for child in sorted(base.iterdir(), reverse=True):
                # Check child directly and child/wasi-sdk
                for candidate in [child, child / "wasi-sdk"]:
                    if (candidate / "bin" / "clang").exists():
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


def _load_toml(path: Path) -> tuple[dict, Path]:
    """Load a toml file, returning (data, base_dir). Merges .hookz.local.toml."""
    with open(path, "rb") as f:
        data = tomllib.load(f)
    base = path.parent

    local_path = base / ".hookz.local.toml"
    if local_path.exists():
        with open(local_path, "rb") as f:
            local_data = tomllib.load(f)
        for section, values in local_data.items():
            if isinstance(values, dict):
                data.setdefault(section, {}).update(values)
            else:
                data[section] = values

    return data, base


def _merge_toml(base: dict, overlay: dict) -> dict:
    """Merge overlay into base (overlay wins). Shallow merge per section."""
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged


def load_config(
    toml_path: Path | None = None,
    source_file: Path | None = None,
) -> HookzConfig:
    """Load config with layered resolution.

    Args:
        toml_path: Explicit path to hookz.toml (skips search).
        source_file: Source .c file being built — used to find a project
            hookz.toml near the source.
    """
    # Track which toml file set each section.key
    key_sources: dict[str, str] = {}
    searched: list[str] = []

    if toml_path is not None:
        toml_data, base = _load_toml(toml_path)
        _tag_sources(key_sources, toml_data, str(toml_path))
        return _build_config(toml_data, base, searched, key_sources)

    merged: dict = {}
    base = Path.cwd()

    # Layer 1: global ~/.config/hookz/hookz.toml
    global_path = _global_config_path()
    searched.append(str(global_path))
    if global_path.exists():
        merged, base = _load_toml(global_path)
        _tag_sources(key_sources, merged, str(global_path))

    # Layer 2: walk up from CWD
    cwd_toml = _find_toml(Path.cwd())
    if cwd_toml:
        cwd_data, cwd_base = _load_toml(cwd_toml)
        merged = _merge_toml(merged, cwd_data)
        base = cwd_base
        _tag_sources(key_sources, cwd_data, str(cwd_toml))
    else:
        searched.append(f"{Path.cwd()} (walked up)")

    # Layer 3: walk up from source file (if different from CWD search)
    if source_file is not None:
        src_toml = _find_toml(source_file.resolve().parent)
        if src_toml and src_toml != cwd_toml:
            src_data, src_base = _load_toml(src_toml)
            merged = _merge_toml(merged, src_data)
            base = src_base
            _tag_sources(key_sources, src_data, str(src_toml))
        elif src_toml is None:
            searched.append(f"{source_file.parent} (walked up)")

    return _build_config(merged, base, searched, key_sources)


def _tag_sources(key_sources: dict[str, str], data: dict, source: str) -> None:
    """Record which source file each key came from (later calls overwrite)."""
    for section, values in data.items():
        if isinstance(values, dict):
            for key in values:
                key_sources[f"{section}.{key}"] = source
        else:
            key_sources[section] = source


def _build_config(toml_data: dict, base: Path,
                  searched: list[str] | None = None,
                  key_sources: dict[str, str] | None = None) -> HookzConfig:
    """Build HookzConfig from merged toml data."""
    sources: dict[str, str] = {}
    if key_sources:
        sources.update(key_sources)
    if searched:
        sources["_searched"] = "; ".join(searched)

    paths_cfg = toml_data.get("paths", {})
    compile_cfg = toml_data.get("compile", {})
    coverage_cfg = toml_data.get("coverage", {})
    hooks_cfg = toml_data.get("hooks", {})

    path_env_aliases = {
        "xahaud": ("HOOKZ_XAHAUD", "HOOKZ_XAHAUD_ROOT"),
        "hook_headers": ("HOOKZ_HOOK_HEADERS",),
        "wasi_sdk": ("HOOKZ_WASI_SDK",),
    }
    for key, env_keys in path_env_aliases.items():
        if key not in paths_cfg:
            for env_key in env_keys:
                if env_key in os.environ:
                    paths_cfg[key] = os.environ[env_key]
                    sources[f"paths.{key}"] = f"env {env_key}"
                    break

    # Default hook_headers to ${xahaud}/hook if xahaud is set
    if "xahaud" in paths_cfg and "hook_headers" not in paths_cfg:
        paths_cfg["hook_headers"] = "${xahaud}/hook"
        sources["paths.hook_headers"] = "default (${xahaud}/hook)"

    # Resolve [paths] in dependency order — multiple passes to handle
    # forward references like hook_headers = "${xahaud}/hook"
    resolved: dict[str, str] = {}
    for _pass in range(3):
        for key, raw in paths_cfg.items():
            env_keys = path_env_aliases.get(key, (f"HOOKZ_{key.upper()}",))
            for env_key in env_keys:
                env_val = os.environ.get(env_key)
                if env_val is not None:
                    raw = env_val
                    sources[f"paths.{key}"] = f"env {env_key}"
                    break
            resolved[key] = str(_resolve_path(raw, base, resolved))

    paths = {k: Path(v) for k, v in resolved.items()}

    # Auto-detect wasi_sdk if not configured
    if "wasi_sdk" not in paths or not (paths["wasi_sdk"] / "bin" / "clang").exists():
        detected = _detect_wasi_sdk()
        if detected:
            paths["wasi_sdk"] = detected
            sources["paths.wasi_sdk"] = f"auto-detected ({detected})"

    # Fall back to xahaud-lite vendored tree for xahaud + hook_headers
    from hookz.xahaud_files import _vendored_root
    vendored = _vendored_root()

    if "xahaud" not in paths or not paths["xahaud"].exists():
        if vendored.exists():
            paths["xahaud"] = vendored
            sources["paths.xahaud"] = "vendored (xahaud-lite)"

    if "hook_headers" not in paths or not paths["hook_headers"].exists():
        if "xahaud" in paths and (paths["xahaud"] / "hook").exists():
            paths["hook_headers"] = paths["xahaud"] / "hook"
            sources["paths.hook_headers"] = "derived (xahaud/hook)"
        elif (vendored / "hook").exists():
            paths["hook_headers"] = vendored / "hook"
            sources["paths.hook_headers"] = "vendored (xahaud-lite/hook)"

    # Compile defaults
    if "compile.target" not in sources:
        sources["compile.target"] = sources.get("compile.target", "default")
    if "compile.exports" not in sources:
        sources["compile.exports"] = "default"

    # Resolve [hooks] with all paths available as variables
    hooks = None
    if hooks_cfg:
        resolved_strs = {k: str(v) for k, v in paths.items()}
        hooks = {}
        for name, source_path in hooks_cfg.items():
            hooks[name] = _resolve_path(source_path, base, resolved_strs)

    return HookzConfig(
        paths=paths,
        hooks=hooks,
        compile_target=compile_cfg.get("target", "wasm32-wasip1"),
        extra_cflags=compile_cfg.get("extra_cflags"),
        exports=compile_cfg.get("exports", ["hook", "cbak"]),
        coverage_threshold=coverage_cfg.get("threshold", 90),
        sources=sources,
    )
