"""hookz — CLI for the hook testing framework."""

from __future__ import annotations

import sys
from pathlib import Path

import click


# ---------------------------------------------------------------------------
# Helper / utility functions (module-level, not nested)
# ---------------------------------------------------------------------------

def _print_legend(console, config):
    """Print path legend so the user knows where sources come from."""
    console.print(f"  [dim]XAHAUD = {config.xahaud_root}[/dim]")
    console.print()


def _xahaud_rel(path: str, config) -> str:
    """Shorten an absolute xahaud path to $XAHAUD/... for display."""
    root = str(config.xahaud_root)
    if path.startswith(root):
        return "$XAHAUD" + path[len(root):]
    return path


def _show_list(console, config) -> int:
    """List all hook API functions with implementation status."""
    from hookz.handlers import collect_handlers
    from hookz.xrpl.xahaud import XahaudRepo

    handlers = collect_handlers()

    _print_legend(console, config)

    # Get all known hook API functions from xahaud
    try:
        repo = XahaudRepo(str(config.xahaud_root))
        all_functions = repo.list_hook_functions()
    except Exception:
        all_functions = []

    # If we can't get the full list, just show what we have
    if not all_functions:
        all_functions = sorted(handlers.keys())

    implemented = 0
    total = len(all_functions)

    for name in sorted(all_functions):
        if name in handlers:
            fn = handlers[name]
            import inspect
            try:
                source_file = Path(inspect.getfile(fn)).name
                line = inspect.getsourcelines(fn)[1]
                loc = f"{source_file}:{line}"
            except (TypeError, OSError):
                loc = fn.__module__
            console.print(f"  [green]✓[/green] {name:30s} {loc}")
            implemented += 1
        else:
            console.print(f"  [red]✗[/red] {name:30s} [dim](stub)[/dim]")

    console.print(f"\n  {implemented}/{total} implemented")
    return 0


def _show_function(console, config, name: str) -> int:
    """Show detailed info for a single function."""
    from rich.panel import Panel
    from hookz.handlers import collect_handlers
    from hookz.xrpl.xahaud import XahaudRepo

    handlers = collect_handlers()

    # Status
    if name in handlers:
        fn = handlers[name]
        import inspect
        try:
            source_file = Path(inspect.getfile(fn)).name
            line = inspect.getsourcelines(fn)[1]
            loc = f"{source_file}:{line}"
        except (TypeError, OSError):
            loc = fn.__module__
        console.print(f"\nStatus: [green]✓ implemented[/green] ({loc})\n")
    else:
        console.print(f"\nStatus: [red]✗ stub[/red] (default no-op handler)\n")

    _print_legend(console, config)

    # xahaud source
    try:
        repo = XahaudRepo(str(config.xahaud_root))

        wrapper_path = "$XAHAUD/src/xrpld/app/hook/detail/applyHook.cpp"
        impl_path = "$XAHAUD/src/xrpld/app/hook/detail/HookAPI.cpp"

        wrapper = repo.find_hook_function(name)
        if wrapper:
            console.print(Panel(wrapper, title=f"Wrapper ({wrapper_path})", border_style="dim"))

        impl = repo.find_api_method(name)
        if impl:
            console.print(Panel(impl, title=f"Implementation ({impl_path})", border_style="blue"))

        test_path = "$XAHAUD/src/test/app/SetHook_test.cpp"
        test_code = repo.find_test_function(name)
        if test_code:
            console.print(Panel(test_code, title=f"Test ({test_path})", border_style="green"))

        if not wrapper and not impl and not test_code:
            console.print(f"[dim]No xahaud source found for '{name}'[/dim]")

    except Exception as e:
        console.print(f"[yellow]Could not load xahaud source: {e}[/yellow]")

    if name not in handlers:
        console.print(f"\n[dim]To implement: add to src/hookz/handlers/[/dim]")
        console.print(f"[dim]  def {name}(rt, ...): ...[/dim]")

    return 0


def _print_guard_result(result) -> None:
    """Print detailed guard check results."""
    max_wce = 65535
    hook_pct = result.hook_wce / max_wce * 100
    print(f"  hook() WCE: {result.hook_wce:,} / {max_wce:,} ({hook_pct:.1f}% of budget)")
    if result.cbak_func_idx is not None:
        cbak_pct = result.cbak_wce / max_wce * 100
        print(f"  cbak() WCE: {result.cbak_wce:,} / {max_wce:,} ({cbak_pct:.1f}% of budget)")
    print(f"  Imports: {result.import_count}")
    print(f"  Guard function: import #{result.guard_func_idx}")


WASM_MAGIC = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'


def _validate_wasm(wasm: bytes, label: str, log) -> None:
    """Quick sanity checks on the output binary.

    Disabled by default. Set HOOKZ_VALIDATE=1 to enable.
    """
    import os
    if not os.environ.get("HOOKZ_VALIDATE"):
        return
    if len(wasm) < 8:
        log(f"  SANITY FAIL: {label} is only {len(wasm)} bytes")
        sys.exit(1)
    if wasm[:4] != WASM_MAGIC:
        log(f"  SANITY FAIL: {label} bad magic: {wasm[:4].hex()} (expected 0061736d)")
        sys.exit(1)
    if wasm[4:8] != WASM_VERSION:
        log(f"  SANITY FAIL: {label} bad version: {wasm[4:8].hex()} (expected 01000000)")
        sys.exit(1)

    # Check for bulk-memory instructions that xahaud rejects
    for i in range(len(wasm) - 1):
        if wasm[i] == 0xFC and wasm[i + 1] in (10, 11):
            name = "memory.copy" if wasm[i + 1] == 10 else "memory.fill"
            log(f"  SANITY FAIL: {label} contains {name} at offset 0x{i:X} (xahaud rejects this)")
            sys.exit(1)

    # Validate sections are parseable
    try:
        from hookz.wasm.decode import decode_module
        mod = decode_module(wasm)
        if mod.hook_export is None:
            log(f"  SANITY FAIL: {label} has no hook() export")
            sys.exit(1)
    except Exception as e:
        log(f"  SANITY FAIL: {label} failed to decode: {e}")
        sys.exit(1)


def _try_optimize(wasm: bytes, log=print) -> bytes:
    """Run wasm-opt if available, return original bytes if not."""
    import platform
    import shutil

    if shutil.which("wasm-opt") is None:
        system = platform.system()
        if system == "Darwin":
            hint = "brew install binaryen"
        elif system == "Linux":
            hint = "apt install binaryen  # or your package manager"
        else:
            hint = "install binaryen from https://github.com/WebAssembly/binaryen/releases"
        log(f"  wasm-opt not found — skipping optimization ({hint})")
        return wasm

    from hookz.wasm.optimize import optimize_hook
    before = len(wasm)
    wasm = optimize_hook(wasm)
    log(f"  Optimized: {before} → {len(wasm)} bytes")
    return wasm


def _print_annotated_source(console, source: Path, opt_locs, debug_locs, result) -> None:
    """Print source code with dual-column WCE: debug vs optimized."""
    from rich.panel import Panel

    # Count instructions per line for both builds
    def _count_per_line(locs) -> dict[int, int]:
        counts: dict[int, int] = {}
        for loc in locs:
            counts[loc.line] = counts.get(loc.line, 0) + 1
        return counts

    opt_counts = _count_per_line(opt_locs)
    debug_counts = _count_per_line(debug_locs)

    # Collect loop lines for markers
    loop_lines: dict[int, int] = {}
    from hookz.wasm.guard import BlockInfo
    def _collect_loop_lines(node: BlockInfo | None) -> None:
        if node is None:
            return
        if node.is_loop and node.guard_id:
            line = node.guard_id & 0x7FFFFFFF
            if 0 < line < 100000:
                loop_lines[line] = node.iteration_bound
        for child in node.children:
            _collect_loop_lines(child)
    _collect_loop_lines(result.hook_tree)
    _collect_loop_lines(result.cbak_tree)

    try:
        src_lines = source.read_text().splitlines()
    except Exception:
        console.print("[yellow]Could not read source file[/yellow]")
        return

    all_lines = set(opt_counts.keys()) | set(debug_counts.keys())

    out = []
    out.append(f" [bold]debug │ prod │      │[/bold]")
    out.append(f" [dim]──────┼──────┼──────┼{'─' * 60}[/dim]")

    for i, line_text in enumerate(src_lines, 1):
        d = debug_counts.get(i, 0)
        o = opt_counts.get(i, 0)

        d_col = f"{d:>5}" if d else "     "
        if o > 0:
            o_col = f"{o:>5}"
        elif d > 0:
            o_col = " [red]ELIM[/red]"
        else:
            o_col = "     "

        ln_col = f"{i:>4}"
        sep = "│"

        if i in loop_lines:
            stripped = line_text.lstrip()
            indent = line_text[:len(line_text) - len(stripped)]
            out.append(f" [bold red]{d_col}[/bold red] {sep} [bold red]{o_col}[/bold red] {sep} [bold]{ln_col}[/bold] {sep} {indent}[red]►[/red] {stripped}")
        elif d > 0 and o == 0:
            out.append(f" [dim]{d_col}[/dim] {sep} [red] ELIM[/red] {sep} [dim]{ln_col}[/dim] {sep} [dim strike]{line_text}[/dim strike]")
        elif o > 0 and d > 0 and o < d:
            out.append(f" {d_col} {sep} [green]{o_col}[/green] {sep} {ln_col} {sep} {line_text}")
        elif o > 0:
            out.append(f" {d_col} {sep} {o_col} {sep} {ln_col} {sep} {line_text}")
        else:
            out.append(f" {d_col} {sep} {o_col} {sep} [dim]{ln_col}[/dim] {sep} [dim]{line_text}[/dim]")

    console.print(Panel(
        "\n".join(out),
        title=f"{source.name} — instructions per line (debug vs prod)",
        border_style="blue",
    ))
    console.print(
        "  [dim]debug = -O0 instrs │ prod = -Oz instrs │ ELIM = removed by optimizer"
        " │ Loop totals (above) are exact.[/dim]"
    )


def _line_from_guard_id(guard_id: int) -> str:
    """Extract source line from guard ID.

    The _g() macro encodes line as: (1 << 31) + __LINE__
    So the line number is guard_id & 0x7FFFFFFF, but only if bit 31 is set.
    """
    if guard_id < 0:
        # Signed: undo two's complement
        line = guard_id & 0x7FFFFFFF
    elif guard_id & 0x80000000:
        line = guard_id & 0x7FFFFFFF
    else:
        line = guard_id  # raw line number
    if 0 < line < 100000:
        return f"line {line}"
    return f"guard 0x{guard_id & 0xFFFFFFFF:08X}"


def _collect_loops(node, /) -> list[tuple[str, int, int]]:
    """Collect all loop nodes with (source_location, bound, wce)."""
    loops = []
    if node.is_loop:
        loc = _line_from_guard_id(node.guard_id)
        loops.append((loc, node.iteration_bound, node.wce))
    for child in node.children:
        loops.extend(_collect_loops(child))
    return loops


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------

class AliasedGroup(click.Group):
    """Allow abbreviated/aliased commands (e.g. 'hookz gc' for guard-check)."""


def _print_version(ctx, _param, value):
    if not value or ctx.resilient_parsing:
        return
    from hookz._version import get_version
    click.echo(f"hookz {get_version()}")
    ctx.exit()


@click.group(cls=AliasedGroup)
@click.option("--version", is_flag=True, callback=_print_version, expose_value=False, is_eager=True, help="Show version.")
def cli():
    """hookz — CLI for the hook testing framework."""


@cli.group()
def config():
    """Configuration and paths."""


@config.command("show")
def config_show():
    """Show resolved configuration with sources."""
    import os
    from hookz.config import load_config, _find_toml, _global_config_path

    cfg = load_config()
    src = cfg.sources
    home = str(Path.home())

    def _short(s: str) -> str:
        return s.replace(home, "~") if home in s else s

    def source_for(key: str) -> str:
        return _short(src.get(key, "default"))

    def _exists(p: Path) -> str:
        return "" if p.exists() else "  # NOT FOUND"

    def _toml_val(v) -> str:
        if isinstance(v, list):
            return "[" + ", ".join(f'"{x}"' for x in v) + "]"
        if isinstance(v, Path):
            return f'"{_short(str(v))}"'
        if isinstance(v, str):
            return f'"{v}"'
        return str(v)

    # Config file locations
    print("# Config resolution order (later wins):")
    global_path = _global_config_path()
    status = "found" if global_path.exists() else "not found"
    print(f"#   1. {_short(str(global_path))}  ({status})")
    cwd_toml = _find_toml()
    if cwd_toml:
        print(f"#   2. {_short(str(cwd_toml))}  (found)")
    else:
        print(f"#   2. hookz.toml  (not found, walked up from {_short(str(Path.cwd()))})")

    env_overrides = {k: v for k, v in os.environ.items()
                     if k.startswith("HOOKZ_") or k == "WASI_SDK_PATH"}
    if env_overrides:
        print("#   3. env: " + ", ".join(f"{k}={_short(v)}" for k, v in sorted(env_overrides.items())))
    print()

    def _line(kv: str, source: str, suffix: str = "") -> None:
        comment = f"# {source}{suffix}"
        inline = f"{kv}  {comment}"
        if len(inline) <= 100:
            print(inline)
        else:
            print(comment)
            print(kv)

    # [paths]
    print("[paths]")
    for key in sorted(cfg.paths):
        val = cfg.paths[key]
        _line(f'{key} = "{_short(str(val))}"',
              source_for(f"paths.{key}"),
              _exists(val))
    print()

    # [compile]
    print("[compile]")
    _line(f'target = "{cfg.compile_target}"', source_for("compile.target"))
    if cfg.extra_cflags:
        _line(f"extra_cflags = {_toml_val(cfg.extra_cflags)}", source_for("compile.extra_cflags"))
    _line(f"exports = {_toml_val(cfg.exports)}", source_for("compile.exports"))
    print()

    # [coverage]
    print("[coverage]")
    _line(f"threshold = {cfg.coverage_threshold}", source_for("coverage.threshold"))

    # [hooks]
    if cfg.hooks:
        print()
        print("[hooks]")
        for name, path in sorted(cfg.hooks.items()):
            _line(f'{name} = "{_short(str(path))}"',
                  source_for(f"hooks.{name}"),
                  _exists(path))


@config.command("path")
@click.argument("name", required=False, default=None)
def config_path(name):
    """Print a config path (for scripting).

    \b
    Names:
      build-cache    Build cache directory (~/.cache/hookz-builds)
      xahaud         Xahaud root (checkout or vendored)
      hook-headers   Hook API header directory
      wasi-sdk       wasi-sdk installation
      config         Active hookz.toml file

    With no NAME, lists all.
    """
    from hookz.config import load_config, _find_toml
    from hookz.build_test_hooks import CompilationCache

    cfg = load_config()

    known = {
        "build-cache": lambda: CompilationCache.DEFAULT_CACHE_DIR,
        "xahaud": lambda: cfg.xahaud_root,
        "hook-headers": lambda: cfg.hook_headers,
        "wasi-sdk": lambda: cfg.wasi_sdk,
        "config": lambda: _find_toml() or "",
    }

    if name is None:
        for k in sorted(known):
            print(f"{k}\t{known[k]()}")
    elif name in known:
        print(known[name]())
    else:
        print(f"Unknown path: {name}", file=sys.stderr)
        print(f"Available: {', '.join(sorted(known))}", file=sys.stderr)
        sys.exit(1)


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
def test(pytest_args):
    """Run tests via pytest (extra args passed through)."""
    import pytest
    sys.exit(pytest.main(list(pytest_args)))


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("pytest_args", nargs=-1, type=click.UNPROCESSED)
def coverage(pytest_args):
    """Run tests and show coverage report."""
    import pytest

    args = list(pytest_args)

    if "-v" not in args and "--verbose" not in args:
        args = ["-v"] + args

    result = pytest.main(args)

    from hookz.config import load_config
    config = load_config()

    for i, a in enumerate(args):
        if a == "--threshold":
            config.coverage_threshold = int(args[i + 1])

    sys.exit(result)


@cli.command("find-tests")
@click.argument("spec")
@click.argument("extra_args", nargs=-1, type=click.UNPROCESSED)
def find_tests(spec, extra_args):
    """Find tests that cover a line range.

    SPEC is <file>:<start>[-<end>], e.g. tip.c:225-400
    """
    import re
    import pytest

    m = re.match(r'(\w+\.\w+):(\d+)(?:-(\d+))?$', spec)
    if not m:
        print(f"Invalid format: {spec}")
        print("Expected: <file>:<start>[-<end>]  e.g. tip.c:225-400")
        sys.exit(1)

    filename = m.group(1)
    start = int(m.group(2))
    end = int(m.group(3)) if m.group(3) else start

    # Run all tests silently to collect per-test coverage
    pytest.main(["-x", "-q", "--tb=no", "--no-header"] + list(extra_args))

    # Query which tests hit those lines
    from hookz.testing.plugin import find_tests_for_lines, _hook_registry

    # Match filename to hook name
    hook_name = None
    for name, path in _hook_registry.items():
        if path.name == filename:
            hook_name = name
            break

    if hook_name is None:
        print(f"No registered hook matches '{filename}'")
        print(f"Registered: {', '.join(f'{n} ({p.name})' for n, p in _hook_registry.items())}")
        sys.exit(1)

    tests = find_tests_for_lines(hook_name, start, end)

    if not tests:
        print(f"No tests cover {filename}:{start}-{end}")
    else:
        print(f"\nTests covering {filename}:{start}-{end}:")
        for t in sorted(tests):
            print(f"  {t}")
        print(f"\n{len(tests)} test(s) found")

    sys.exit(0)


@cli.command()
@click.option("--list", "list_all", is_flag=True, help="List all hook API functions and their status.")
@click.argument("name", required=False)
def show(list_all, name):
    """Show hook API function implementation from xahaud source.

    With --list, shows all functions and their implementation status.
    With a NAME argument, shows detailed info for that function.
    """
    from rich.console import Console
    from hookz.config import load_config

    console = Console()
    config = load_config()

    if list_all or name is None:
        sys.exit(_show_list(console, config))
    else:
        sys.exit(_show_function(console, config, name))


@cli.command("debug-compile")
@click.argument("source", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), default=None, help="Output WASM file path.")
def debug_compile(source, output):
    """Check if a hook compiles (debug build, not for deployment)."""
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    source = Path(source)
    if output is None:
        output = source.with_suffix(".wasm")
    else:
        output = Path(output)

    config = load_config()
    wasm = compile_hook(source, output, config, debug=True, optimize=False)
    print(f"Debug-compiled {source.name} → {output} ({len(wasm)} bytes)")
    sys.exit(0)


@cli.command()
@click.argument("source", default="-")
@click.option("-o", "--output", default=None, help="Output file path (default: stdout for stdin, SOURCE.wasm for files).")
@click.option("--coverage", is_flag=True, help="Instrument with __on_source_line coverage callbacks.")
def build(source, output, coverage):
    """Compile, clean, and guard-check a hook.

    SOURCE can be a file path or '-' for stdin. Output goes to stdout
    by default when reading from stdin, or to SOURCE.wasm for files.
    """
    import os
    import tempfile
    from hookz.config import load_config

    if os.environ.get("HOOKZ_NO_COVERAGE"):
        coverage = False

    if source == "-":
        stdin_data = sys.stdin.buffer.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".c", delete=False)
        tmp.write(stdin_data)
        tmp.close()
        source = Path(tmp.name)
        stdout_mode = output is None
    else:
        source = Path(source)
        if not source.exists():
            print(f"Error: source file '{source}' not found", file=sys.stderr)
            sys.exit(1)
        stdout_mode = False

    if output is not None:
        stdout_mode = output in ("-", "/dev/stdout")
        if not stdout_mode:
            output = Path(output)

    if output is None and not stdout_mode:
        output = source.with_suffix(".wasm")

    config = load_config(source_file=source)

    if coverage:
        _build_coverage(source, output, config, stdout_mode)
    else:
        _build_normal(source, output, config, stdout_mode)


def _build_normal(source: Path, output, config, stdout_mode: bool = False) -> None:
    """Standard production build pipeline."""
    from hookz.compiler import compile_hook
    from hookz.wasm.clean import clean_hook, CleanError
    from hookz.wasm.guard import validate_guards, GuardError

    # Status messages go to stderr so stdout is clean for binary output
    log = print if not stdout_mode else lambda *a, **k: print(*a, file=sys.stderr, **k)

    # 1. Compile
    log(f"Compiling {source.name}...")
    wasm = compile_hook(source, output if not stdout_mode else None, config, debug=False, optimize=True)
    log(f"  Compiled: {len(wasm)} bytes")

    # 2. Optimize (if wasm-opt available)
    wasm = _try_optimize(wasm, log)

    # 3. Clean
    try:
        cleaned = clean_hook(wasm)
        log(f"  Cleaned: {len(wasm)} → {len(cleaned)} bytes")
    except CleanError as e:
        log(f"  Clean FAILED: {e}")
        sys.exit(1)

    # 4. Guard check
    try:
        result = validate_guards(cleaned)
        hook_pct = result.hook_wce / 65535 * 100
        log(f"  Guard check PASSED (hook WCE={result.hook_wce:,} — {hook_pct:.1f}% of budget)")
    except GuardError as e:
        log(f"  Guard check FAILED: {e}")
        sys.exit(1)

    # 5. Sanity check
    _validate_wasm(cleaned, source.name, log)

    # Write output
    if stdout_mode:
        sys.stdout.buffer.write(cleaned)
    else:
        output.write_bytes(cleaned)
        log(f"  → {output} ({len(cleaned)} bytes)")
    sys.exit(0)


def _build_coverage(source: Path, output, config, stdout_mode: bool = False) -> None:
    """Coverage-instrumented build pipeline.

    Pipeline: two-stage compile (DWARF) → instrument → clean → guard-check
    """
    from hookz.compiler import compile_hook_two_stage
    from hookz.coverage.rewriter import instrument_wasm
    from hookz.wasm.clean import clean_hook, CleanError
    from hookz.wasm.guard import validate_guards, GuardError
    from hookz.wasm.whitelist import get_whitelist

    log = print if not stdout_mode else lambda *a, **k: print(*a, file=sys.stderr, **k)

    # 1. Two-stage compile: clang -c -g → wasm-ld (preserves DWARF)
    from hookz.compiler import COVERAGE_OPT_LEVEL
    log(f"Compiling {source.name} (two-stage, {COVERAGE_OPT_LEVEL} with DWARF)...")
    wasm = compile_hook_two_stage(source, config, opt_level=COVERAGE_OPT_LEVEL)
    log(f"  Compiled: {len(wasm)} bytes")

    # 2. Instrument with __on_source_line callbacks
    log("  Instrumenting for coverage...")
    wasm, locs = instrument_wasm(wasm)
    log(f"  Instrumented: {len(wasm)} bytes ({len(locs)} source locations)")

    # 3. Clean (strips custom sections, rewrites guards)
    #    coverage_call_idx=0 tells the guard rewriter that calls to import #0
    #    (__on_source_line) are transparent — their i32.const args should not
    #    pollute guard detection.
    try:
        cleaned = clean_hook(wasm, coverage_call_idx=0)
        log(f"  Cleaned: {len(wasm)} → {len(cleaned)} bytes")
    except CleanError as e:
        log(f"  Clean FAILED: {e}")
        sys.exit(1)

    # 4. Guard check with __on_source_line in the whitelist
    try:
        coverage_whitelist = get_whitelist() | {"__on_source_line"}
        result = validate_guards(cleaned, import_whitelist=coverage_whitelist)
        hook_pct = result.hook_wce / 65535 * 100
        log(f"  Guard check PASSED (hook WCE={result.hook_wce:,} — {hook_pct:.1f}% of budget)")
    except GuardError as e:
        log(f"  Guard check FAILED: {e}")
        sys.exit(1)

    # 5. Sanity check
    _validate_wasm(cleaned, source.name, log)

    # Write output
    if stdout_mode:
        sys.stdout.buffer.write(cleaned)
    else:
        output.write_bytes(cleaned)
        log(f"  → {output} ({len(cleaned)} bytes, coverage-instrumented)")
    sys.exit(0)


@cli.command()
@click.argument("input_wasm", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), default=None, help="Output WASM file path (default: overwrite input).")
def clean(input_wasm, output):
    """Clean a hook WASM binary for deployment."""
    from hookz.wasm.clean import clean_hook, CleanError

    source = Path(input_wasm)
    if output is None:
        output = source  # overwrite by default
    else:
        output = Path(output)

    wasm = source.read_bytes()
    try:
        cleaned = clean_hook(wasm)
    except CleanError as e:
        print(f"Clean failed: {e}")
        sys.exit(1)

    output.write_bytes(cleaned)
    print(f"Cleaned {source.name}: {len(wasm)} → {len(cleaned)} bytes → {output}")
    sys.exit(0)


@cli.command("guard-check")
@click.argument("hook_wasm", type=click.Path(exists=True))
def guard_check(hook_wasm):
    """Validate guard calls in a hook WASM binary."""
    from hookz.wasm.guard import validate_guards, GuardError

    source = Path(hook_wasm)
    wasm = source.read_bytes()

    try:
        result = validate_guards(wasm)
    except GuardError as e:
        print(f"Guard check FAILED: {e}")
        if e.codesec >= 0:
            print(f"  Code section: {e.codesec}, byte offset: {e.offset}")
        sys.exit(1)

    print(f"Guard check PASSED: {source.name}")
    _print_guard_result(result)
    sys.exit(0)


@cli.command()
@click.argument("source", type=click.Path(exists=True))
@click.option("--source", "-s", "show_source", is_flag=True, help="Show annotated source with instruction counts.")
def wce(source, show_source):
    """Analyze WCE budget usage with source line mapping."""
    from rich.console import Console
    from hookz.compiler import compile_hook
    from hookz.config import load_config
    from hookz.wasm.guard import GuardError, BlockInfo
    from hookz.coverage.rewriter import parse_dwarf_locations

    console = Console()
    source = Path(source)
    config = load_config()

    # Two-stage compile: clang -c -g -Oz -> wasm-ld (preserves DWARF on optimized code)
    from hookz.compiler import compile_hook_two_stage
    from hookz.wasm.clean import clean_hook_detailed
    from hookz.wasm.visitor import KeepDebugVisitor
    from hookz.wasm.guard import analyze_wce

    try:
        wasm = compile_hook_two_stage(source, config, opt_level="-Oz")
        console.print(f"[dim]Compiled {source.name} ({len(wasm)} bytes, optimized with DWARF)[/dim]")
    except Exception as e:
        # Fall back to single-stage debug build
        console.print(f"[dim]Two-stage compile failed ({e}), falling back to debug build[/dim]")
        wasm = compile_hook(source, config=config, debug=True, optimize=False)
        console.print(f"[dim]Compiled {source.name} ({len(wasm)} bytes, debug build)[/dim]")

    # Clean with DWARF preserved (rewrite guards, keep .debug_line)
    try:
        clean_result = clean_hook_detailed(wasm, visitor=KeepDebugVisitor())
        cleaned = clean_result.wasm
    except Exception:
        cleaned = wasm

    # Parse DWARF from cleaned binary (addresses match the cleaned code)
    try:
        dwarf_locs = parse_dwarf_locations(cleaned)
    except Exception:
        dwarf_locs = []

    # Analyze WCE on cleaned binary
    result = analyze_wce(cleaned)

    max_wce = 65535

    # Also compile debug build for comparison
    debug_result = None
    debug_dwarf_locs = []
    try:
        debug_wasm = compile_hook(source, config=config, debug=True, optimize=False)
        from hookz.wasm.clean import clean_hook_detailed as _clean_d
        debug_cleaned = _clean_d(debug_wasm, visitor=KeepDebugVisitor()).wasm
        debug_dwarf_locs = parse_dwarf_locations(debug_cleaned)
        debug_result = analyze_wce(debug_cleaned)
    except Exception:
        pass

    # Source view first (if requested)
    if show_source and source.suffix == ".c":
        _print_annotated_source(console, source, dwarf_locs, debug_dwarf_locs, result)

    # Then summary at the end
    console.print()
    console.print(f"[bold]{source.name}[/bold] — Worst-Case Execution Summary")
    console.print()

    for label, opt_wce, opt_tree, dbg_wce, dbg_tree in [
        ("hook()", result.hook_wce, result.hook_tree,
         debug_result.hook_wce if debug_result else 0,
         debug_result.hook_tree if debug_result else None),
        ("cbak()", result.cbak_wce, result.cbak_tree,
         debug_result.cbak_wce if debug_result else 0,
         debug_result.cbak_tree if debug_result else None),
    ]:
        if opt_tree is None:
            continue
        pct = opt_wce / max_wce * 100
        bar_filled = int(pct / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        savings = ""
        if dbg_wce and dbg_wce > opt_wce:
            saved_pct = (1 - opt_wce / dbg_wce) * 100
            savings = f"  [green]({saved_pct:.0f}% smaller than debug)[/green]"
        console.print(f"  [bold]{label}[/bold] WCE: {opt_wce:,} / {max_wce:,} ({pct:.1f}%)  {bar}{savings}")
        console.print()

        # Dual-column loop breakdown
        opt_loops = _collect_loops(opt_tree)
        dbg_loops = _collect_loops(dbg_tree) if dbg_tree else []

        if not opt_loops:
            console.print("    [dim]No loops found[/dim]")
            continue

        # Build lookup by line for debug loops
        dbg_loop_by_line: dict[str, int] = {loc: wce for loc, _, wce in dbg_loops}

        console.print(f"    [bold]{'':>20s}  {'':>10s}  {'debug':>8s}  {'prod':>8s}[/bold]")
        opt_loops.sort(key=lambda x: x[2], reverse=True)
        for loc, bound, loop_wce in opt_loops:
            loop_pct = loop_wce / max(opt_wce, 1) * 100
            lbar_filled = int(loop_pct / 5)
            lbar = "█" * lbar_filled + "░" * (20 - lbar_filled)
            dbg_wce_str = f"{dbg_loop_by_line.get(loc, 0):>6,}" if loc in dbg_loop_by_line else "     —"
            console.print(
                f"    {loc:>20s}  GUARD({bound:<5d})  {dbg_wce_str}  {loop_wce:>6,}  {lbar}  {loop_pct:4.1f}%"
            )
        console.print()

    if result.errors:
        console.print(f"  [yellow]⚠ {len(result.errors)} warning(s):[/yellow]")
        for err in result.errors:
            console.print(f"    [dim]{err}[/dim]")
        console.print()

    sys.exit(0)


@cli.command("build-test-hooks")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("-j", "--jobs", type=int, default=0, help="Parallel workers (default: CPU count).")
@click.option("--force-write", is_flag=True, help="Always write output even if unchanged.")
@click.option("--hooks-c-dir", "hooks_c_dir_raw", multiple=True,
              help="Hook source dirs as domain=path (e.g. tipbot=~/hooks). Repeatable.")
@click.option("--hook-coverage/--no-hook-coverage", default=False,
              help="Compile with coverage instrumentation.")
@click.option("--no-cache", is_flag=True, help="Bypass compilation cache.")
def build_test_hooks(input_file, jobs, force_write, hooks_c_dir_raw, hook_coverage, no_cache):
    """Generate _hooks.h from a C++ test file containing WASM blocks.

    Extracts inline hooks (R"[test.hook](...)[test.hook]") and file
    references ("file:domain/path.c"), compiles each to WASM, and
    writes a C++ header with the bytecode.

    \b
    Examples:
        hookz build-test-hooks SetHook_test.cpp
        hookz build-test-hooks Tip_test.cpp --hooks-c-dir tipbot=~/hooks
        hookz build-test-hooks Test.cpp --hook-coverage -j 8
    """
    import os
    import logging as _logging
    from hookz.build_test_hooks import TestHookBuilder

    if os.environ.get("HOOKZ_NO_COVERAGE"):
        hook_coverage = False

    _logging.basicConfig(
        level=_logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    hooks_c_dirs: dict[str, Path] = {}
    for entry in hooks_c_dir_raw:
        if "=" not in entry:
            print(f'Error: invalid --hooks-c-dir "{entry}". Expected domain=path', file=sys.stderr)
            sys.exit(1)
        domain, dir_path = entry.split("=", 1)
        resolved = Path(dir_path).expanduser().resolve()
        if not resolved.is_dir():
            print(f'Error: --hooks-c-dir "{domain}": not found: {resolved}', file=sys.stderr)
            sys.exit(1)
        hooks_c_dirs[domain] = resolved

    try:
        builder = TestHookBuilder(
            input_file=input_file,
            jobs=jobs,
            force_write=force_write,
            hooks_c_dirs=hooks_c_dirs or None,
            coverage=hook_coverage,
            no_cache=no_cache,
        )
        builder.build()
    except RuntimeError as e:
        print(f"Build failed: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point — referenced in pyproject.toml [project.scripts]
# ---------------------------------------------------------------------------

def main():
    cli(standalone_mode=False)


if __name__ == "__main__":
    main()
