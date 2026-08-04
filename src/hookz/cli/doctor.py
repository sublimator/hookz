"""hookz doctor — diagnose installation and configuration issues.

Checks the toolchain (wasi-sdk, llvm-dwarfdump, wasm-opt, docker), the
resolved config (hookz.toml, hook headers, hook sources), and finishes
with an end-to-end smoke test: compile a tiny hook, instrument it, run
it in wasmtime, and check coverage hits land.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

_SMOKE_HOOK = """\
#include <stdint.h>

extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
extern int64_t _g(uint32_t id, uint32_t maxiter);

int64_t cbak(uint32_t reserved) { return 0; }

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    return accept(0, 0, 0);
}
"""


def _short(s: str) -> str:
    home = str(Path.home())
    return s.replace(home, "~") if home in s else s


def _report_pin_drift(rep, xahaud_root: Path) -> None:
    """Compare the configured checkout against the ported xahaud revision.

    Drift is informational, not a failure: a checkout may sit on any branch.
    It means the guard checker was ported against different C++ than the files
    present, so `Guard.h:NNN` citations and behaviour may not line up.
    """
    from hookz.wasm.xahaud_ref import XAHAUD_COMMIT, XAHAUD_REF, check_drift

    findings = check_drift(xahaud_root)
    pin = f"{XAHAUD_REF} @ {XAHAUD_COMMIT[:8]}"
    if not findings:
        rep.ok("xahaud pin", f"checkout matches ported revision ({pin})")
        return
    rep.info("xahaud pin", f"checkout differs from ported revision ({pin})")
    for f in findings:
        rep.info("", f"  {f}")


def _first_line(cmd: list[str]) -> str | None:
    """Run a command and return the first line of its output, or None."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (r.stdout or r.stderr).strip()
    return out.splitlines()[0] if out else None


class _Report:
    """Collects check results and renders them as they happen."""

    def __init__(self, console):
        self.console = console
        self.failures: list[str] = []
        self.missing_optional: list[str] = []

    def section(self, title: str) -> None:
        self.console.print(f"\n[bold]{title}[/bold]")

    def ok(self, label: str, detail: str = "") -> None:
        self.console.print(f"  [green]✓[/green] {label:16s} {detail}")

    def fail(self, label: str, detail: str = "", hint: str = "") -> None:
        self.failures.append(label)
        self.console.print(f"  [red]✗[/red] {label:16s} {detail}")
        if hint:
            self.console.print(f"    [dim]→ {hint}[/dim]")

    def optional(self, label: str, detail: str = "", hint: str = "") -> None:
        self.missing_optional.append(label)
        self.console.print(f"  [yellow]–[/yellow] {label:16s} {detail}")
        if hint:
            self.console.print(f"    [dim]→ {hint}[/dim]")

    def info(self, label: str, detail: str = "") -> None:
        self.console.print(f"  [dim]·[/dim] {label:16s} [dim]{detail}[/dim]")


def _binaryen_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return "brew install binaryen"
    if system == "Linux":
        return "apt install binaryen  (or your package manager)"
    return "install binaryen: https://github.com/WebAssembly/binaryen/releases"


def _check_environment(rep: _Report, cfg, cfg_error: Exception | None) -> tuple[bool, list[str] | None]:
    """Check tools. Returns (wasi_ok, dwarfdump_cmd_or_None)."""
    import sys

    rep.section("Environment")

    # Python
    v = sys.version_info
    py = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 12):
        rep.ok("python", py)
    else:
        rep.fail("python", f"{py} (need >= 3.12)")

    # wasmtime
    try:
        from importlib.metadata import version
        rep.ok("wasmtime", version("wasmtime"))
    except Exception as e:
        rep.fail("wasmtime", str(e), hint="uv sync  (wasmtime is a core dependency)")

    # wasi-sdk (via resolved config, includes auto-detection)
    from hookz.config import _global_config_path

    wasi_ok = False
    if cfg_error is not None:
        rep.fail("wasi-sdk", f"config error: {cfg_error}")
    else:
        clang = cfg.wasi_sdk / "bin" / "clang"
        if clang.exists():
            ver = _first_line([str(clang), "--version"]) or ""
            src = cfg.sources.get("paths.wasi_sdk", "hookz.toml")
            rep.ok("wasi-sdk", f"{_short(str(cfg.wasi_sdk))}  [dim]({_short(src)})[/dim]")
            if ver:
                rep.info("", ver)
            wasi_ok = True
        else:
            rep.fail(
                "wasi-sdk", "not found",
                hint=f"mise install wasi-sdk, or set wasi_sdk in hookz.toml / "
                     f"{_short(str(_global_config_path()))} / HOOKZ_WASI_SDK",
            )

    # llvm-dwarfdump (coverage instrumentation)
    dwarfdump: list[str] | None = None
    try:
        from hookz.coverage.rewriter import _find_llvm_dwarfdump
        dwarfdump = _find_llvm_dwarfdump()
        rep.ok("llvm-dwarfdump", " ".join(dwarfdump))
    except RuntimeError:
        rep.fail(
            "llvm-dwarfdump", "not found (needed for coverage)",
            hint="macOS: xcode-select --install   Linux: apt install llvm",
        )

    # wasm-opt (optional)
    wasm_opt = shutil.which("wasm-opt")
    if wasm_opt:
        ver = _first_line(["wasm-opt", "--version"]) or ""
        rep.ok("wasm-opt", ver)
    else:
        rep.optional("wasm-opt", "not found (optional — size optimization)",
                     hint=_binaryen_hint())

    # docker (optional — xahaud integration mode)
    docker = shutil.which("docker")
    if docker:
        ver = _first_line(["docker", "--version"]) or ""
        rep.ok("docker", ver)
    else:
        rep.optional("docker", "not found (optional — xahaud integration tests)")

    return wasi_ok, dwarfdump


def _check_config(rep: _Report, cfg, cfg_error: Exception | None) -> None:
    rep.section("Config")

    from hookz.config import _find_toml, _global_config_path

    global_path = _global_config_path()
    if global_path.exists():
        rep.ok("global config", _short(str(global_path)))
    else:
        rep.info("global config", f"{_short(str(global_path))} (not found — optional)")

    toml = _find_toml()
    if toml:
        rep.ok("hookz.toml", _short(str(toml)))
        local = toml.parent / ".hookz.local.toml"
        if local.exists():
            rep.info("local overrides", _short(str(local)))
    else:
        rep.info("hookz.toml", "not found (walked up from CWD — fine for hookz build)")

    if cfg_error is not None:
        rep.fail("config parse", str(cfg_error))
        return

    # hook headers (vendored fallback is fine)
    src = cfg.sources.get("paths.hook_headers", "")
    if cfg.hook_headers.exists():
        rep.ok("hook headers", f"{_short(str(cfg.hook_headers))}  [dim]({_short(src)})[/dim]")
    else:
        rep.fail("hook headers", "not found (vendored xahaud-lite missing?)",
                 hint="reinstall hookz — src/hookz/xahaud_lite should be bundled")

    # xahaud checkout (optional — vendored fallback covers hookz show)
    xahaud_src = cfg.sources.get("paths.xahaud", "")
    if "vendored" in xahaud_src:
        rep.info("xahaud", "vendored xahaud-lite (set paths.xahaud for full source in hookz show)")
    elif cfg.xahaud_root.exists() and cfg.xahaud_root != Path():
        rep.ok("xahaud", f"{_short(str(cfg.xahaud_root))}  [dim]({_short(xahaud_src)})[/dim]")
        _report_pin_drift(rep, cfg.xahaud_root)
    else:
        rep.optional("xahaud", "no checkout configured (optional — hookz show falls back to vendored headers)")

    # configured hooks
    if cfg.hooks:
        missing = {name: p for name, p in cfg.hooks.items() if not p.exists()}
        if missing:
            names = ", ".join(f"{n} ({_short(str(p))})" for n, p in missing.items())
            rep.fail("hooks", f"{len(missing)}/{len(cfg.hooks)} sources missing: {names}")
        else:
            rep.ok("hooks", f"{len(cfg.hooks)} configured, all sources exist")

    # active env overrides
    overrides = sorted(k for k in os.environ if k.startswith("HOOKZ_") or k == "WASI_SDK_PATH")
    if overrides:
        rep.info("env overrides", ", ".join(overrides))

    # build cache — probe the nearest existing ancestor (dir may not exist yet)
    from hookz.build_test_hooks import CompilationCache
    cache_dir = CompilationCache.DEFAULT_CACHE_DIR
    probe = cache_dir
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if os.access(probe, os.W_OK):
        rep.ok("build cache", _short(str(cache_dir)))
    else:
        rep.fail("build cache", f"{_short(str(cache_dir))} not writable")


def _smoke_test(rep: _Report, dwarfdump_ok: bool) -> None:
    rep.section("Smoke test")

    import tempfile
    from hookz.compiler import compile_hook
    from hookz.runtime import HookRuntime

    src_path: Path | None = None
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w")
        tmp.write(_SMOKE_HOOK)
        tmp.close()
        src_path = Path(tmp.name)

        t0 = time.monotonic()
        wasm = compile_hook(src_path)
        compile_ms = (time.monotonic() - t0) * 1000
        rep.ok("compile", f"{len(wasm)} bytes in {compile_ms:.0f}ms")

        rt = HookRuntime()
        t0 = time.monotonic()
        result = rt.run(wasm, label="doctor.c", coverage=dwarfdump_ok)
        run_ms = (time.monotonic() - t0) * 1000
        if result.error is not None:
            rep.fail("run", f"hook errored: {result.error}")
        elif not result.accepted:
            rep.fail("run", "hook did not call accept()")
        elif dwarfdump_ok and not rt.coverage.all_hits:
            rep.fail("coverage", "instrumented run recorded no line hits")
        else:
            cov = f", {len(rt.coverage.all_hits)} coverage hits" if dwarfdump_ok else " (coverage skipped)"
            rep.ok("run", f"accept() in {run_ms:.0f}ms{cov}")
    except Exception as e:
        rep.fail("smoke test", str(e))
    finally:
        if src_path is not None:
            src_path.unlink(missing_ok=True)


def _check_guard_rules(rep: _Report) -> None:
    """Which guard rules are in force, and why.

    The nesting limit and the memory.copy ban are not hookz's choices — they
    are amendments, and a reader who sees "16" deserves to see which vote made
    it 16 rather than having to trust a constant.
    """
    from hookz import amendments as amd
    from hookz.wasm.guard import nesting_limit

    rep.section("Guard rules (xahaud:include/xrpl/hook/Enum.h:451)")
    try:
        version = amd.guard_rules_version()
    except Exception as e:                                     # noqa: BLE001
        rep.optional("rules", f"could not read the manifest: {e}",
                     "regenerate with x-inspect-net amendments")
        return

    rep.info("network", amd.provenance())
    rep.info("rulesVersion", f"0x{version:02X}")
    for line in amd.guard_rules_explained():
        rep.info("", line)
    rep.info("nesting limit", str(nesting_limit(version)))


def run_doctor(console, smoke: bool = True) -> int:
    """Run all checks. Returns process exit code (0 = healthy)."""
    rep = _Report(console)

    try:
        from hookz.config import load_config
        cfg, cfg_error = load_config(), None
    except Exception as e:
        cfg, cfg_error = None, e

    wasi_ok, dwarfdump = _check_environment(rep, cfg, cfg_error)
    _check_config(rep, cfg, cfg_error)
    _check_guard_rules(rep)

    if smoke and wasi_ok:
        _smoke_test(rep, dwarfdump_ok=dwarfdump is not None)
    elif smoke:
        rep.section("Smoke test")
        rep.info("skipped", "wasi-sdk not found")

    console.print()
    if rep.failures:
        console.print(f"[red]✗ {len(rep.failures)} problem(s):[/red] {', '.join(rep.failures)}")
        return 1
    if rep.missing_optional:
        console.print(f"[green]✓ all required checks passed[/green] "
                      f"[dim]({len(rep.missing_optional)} optional missing: "
                      f"{', '.join(rep.missing_optional)})[/dim]")
    else:
        console.print("[green]✓ all checks passed[/green]")
    return 0
