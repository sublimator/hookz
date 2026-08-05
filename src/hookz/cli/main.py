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
    from rich.text import Text
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
        console.print("\nStatus: [red]✗ stub[/red] (default no-op handler)\n")

    _print_legend(console, config)

    # xahaud source — Text so C brackets are not Rich markup
    try:
        repo = XahaudRepo(str(config.xahaud_root))

        wrapper_path = "$XAHAUD/src/xrpld/app/hook/detail/applyHook.cpp"
        impl_path = "$XAHAUD/src/xrpld/app/hook/detail/HookAPI.cpp"

        wrapper = repo.find_hook_function(name)
        if wrapper:
            console.print(Panel(
                Text(wrapper), title=f"Wrapper ({wrapper_path})", border_style="dim"))

        impl = repo.find_api_method(name)
        if impl:
            console.print(Panel(
                Text(impl), title=f"Implementation ({impl_path})", border_style="blue"))

        test_path = "$XAHAUD/src/test/app/SetHook_test.cpp"
        test_code = repo.find_test_function(name)
        if test_code:
            console.print(Panel(
                Text(test_code), title=f"Test ({test_path})", border_style="green"))

        if not wrapper and not impl and not test_code:
            console.print(f"[dim]No xahaud source found for '{name}'[/dim]")

    except Exception as e:
        console.print(f"[yellow]Could not load xahaud source: {e}[/yellow]")

    if name not in handlers:
        console.print("\n[dim]To implement: add to src/hookz/handlers/[/dim]")
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


def waiver_options(fn):
    """--ignore-* flags for the limits xahaud enforces but an audit may not want.

    Each waives one check so the run reaches the next one. Anything waived is
    reported loudly and marks the result non-deployable.
    """
    fn = click.option(
        "--ignore-depth", is_flag=True,
        help="Waive the block nesting limit (WCE is then computed at full depth).",
    )(fn)
    fn = click.option(
        "--ignore-wce-overage", is_flag=True,
        help="Waive the 65,535 instruction budget.",
    )(fn)
    fn = click.option(
        "--ignore-guard-calls", is_flag=True,
        help="Waive the 1,024 guard-call limit.",
    )(fn)
    fn = click.option(
        "--depth32", is_flag=True,
        help="Override: assume fixGuardDepth32 is in force (nesting limit 32). "
             "Normally read from the network's amendments.",
    )(fn)
    return fn


def _waivers(ignore_depth, ignore_wce_overage, ignore_guard_calls):
    from hookz.wasm.guard import IGNORE_DEPTH, IGNORE_WCE, IGNORE_GUARD_CALLS
    selected = set()
    if ignore_depth:
        selected.add(IGNORE_DEPTH)
    if ignore_wce_overage:
        selected.add(IGNORE_WCE)
    if ignore_guard_calls:
        selected.add(IGNORE_GUARD_CALLS)
    return frozenset(selected)


def _rules(depth32: bool) -> int:
    """The network's guard rules, plus whatever the user asked to assume.

    The base used to be the constant GUARD_RULE_FIX_20250131, which is what
    mainnet happens to run — right by coincidence, and unable to notice the
    network moving. --depth32 stays as an override because "what would this
    hook do under depth32" is a legitimate question to ask of a network that
    has not voted it in.
    """
    from hookz.wasm.guard import GUARD_RULE_DEPTH_32, resolve_rules
    return resolve_rules(None) | (GUARD_RULE_DEPTH_32 if depth32 else 0)


def _report_waived(result, log=print) -> None:
    """A waived limit is a rejection that was asked to keep going. Say so."""
    if not result.waived:
        return
    log("")
    log("  !! NOT DEPLOYABLE — xahaud would REJECT this hook:")
    for w in result.waived:
        log(f"       {w}")
    log("  !! Waived for analysis only. Do not submit this binary via SetHook.")


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


def _print_annotated_source(console, source: Path, opt_locs, debug_locs, result) -> None:
    """Print an explicitly non-authoritative source-attribution aid.

    These rows come from DWARF-friendly analysis twins. They are useful for
    navigation, but are neither instruction ownership nor WCE in the exact
    artifact reported above them.
    """
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

    from rich.markup import escape

    out = []
    # Column labels stay 5 wide, like the counts under them; which binaries
    # these came from is spelled out in the caption below the panel. The rule
    # segments are 6/7/6 because the separators sit at 7, 15 and 22.
    out.append(" [bold]debug │   -Oz │      │[/bold]")
    out.append(f" [dim]──────┼───────┼──────┼{'─' * 60}[/dim]")

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
        # C source can contain [i], [bold], etc. — escape before markup join
        safe = escape(line_text)

        if i in loop_lines:
            stripped = line_text.lstrip()
            indent = line_text[:len(line_text) - len(stripped)]
            out.append(
                f" [bold red]{d_col}[/bold red] {sep} [bold red]{o_col}[/bold red] "
                f"{sep} [bold]{ln_col}[/bold] {sep} {indent}[red]►[/red] {escape(stripped)}"
            )
        elif d > 0 and o == 0:
            out.append(
                f" [dim]{d_col}[/dim] {sep} [red] ELIM[/red] {sep} "
                f"[dim]{ln_col}[/dim] {sep} [dim strike]{safe}[/dim strike]"
            )
        elif o > 0 and d > 0 and o < d:
            out.append(f" {d_col} {sep} [green]{o_col}[/green] {sep} {ln_col} {sep} {safe}")
        elif o > 0:
            out.append(f" {d_col} {sep} {o_col} {sep} {ln_col} {sep} {safe}")
        else:
            out.append(f" {d_col} {sep} {o_col} {sep} [dim]{ln_col}[/dim] {sep} [dim]{safe}[/dim]")

    console.print(Panel(
        "\n".join(out),
        title=f"{source.name} — analysis-twin DWARF rows (not artifact WCE)",
        border_style="blue",
    ))
    console.print(
        "  [yellow]Secondary estimate only:[/yellow] debug/-Oz are DWARF row "
        "counts from different binaries. ELIM means absent from the -Oz twin, "
        "not a measured saving in the exact artifact."
    )


def _line_from_guard_id(guard_id: int, line_map: dict[int, int] | None = None) -> str:
    """Extract source line from guard ID.

    The _g() macro encodes line as: (1 << 31) + __LINE__
    So the line number is guard_id & 0x7FFFFFFF, but only if bit 31 is set.

    line_map maps the artifact's line numbers back into the annotated file,
    and is passed only when the build that produced the artifact stripped
    annotations first. Applying it to an unstripped build's ids would move
    every citation onto unrelated code.

    TODO(guard-line-citation-provenance): assumes the id's __LINE__ belongs to
    the hook's own .c file. GUARD is a function-like macro, so expansion puts
    it there for every in-tree hook — but a guard reached from an inline
    function in a header would carry that header's line, be looked up in the .c
    file's map, and be printed with the same confidence as a correct citation.
    Nothing in the id says which file it came from, so resolving this needs the
    DWARF file index or a per-file guard-id namespace; until then the honest
    fallback is to cite the raw id when the mapped line cannot be corroborated.
    """
    if guard_id < 0:
        # Signed: undo two's complement
        line = guard_id & 0x7FFFFFFF
    elif guard_id & 0x80000000:
        line = guard_id & 0x7FFFFFFF
    else:
        line = guard_id  # raw line number
    if 0 < line < 100000:
        mapped = (line_map or {}).get(line)
        if mapped is not None and mapped != line:
            return f"line {mapped} (artifact {line})"
        return f"line {line}"
    return f"guard 0x{guard_id & 0xFFFFFFFF:08X}"


def _annotated_line_map(source: Path) -> dict[int, int]:
    """Published line -> annotated line, built once per report.

    annotated_line() rebuilds and linearly scans the whole map per lookup;
    a hook with twenty loops re-read and re-parsed the file twenty times.
    """
    from hookz.annotations import line_map

    return {
        published: annotated
        for annotated, published in line_map(source.read_text()).items()
    }


def _collect_loops(
    node, /, line_map: dict[int, int] | None = None
) -> list[tuple[str, int, int]]:
    """Collect all loop nodes with (source_location, bound, wce).

    Iterative for the same reason as the guard checker's loop walk: the tree
    is as deep as the binary nests, and `hookz wce` runs on exactly the hooks
    that nest too deeply. Recursion here turned an over-depth hook into a
    RecursionError traceback instead of a report.
    """
    loops = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.is_loop:
            loops.append((
                _line_from_guard_id(n.guard_id, line_map),
                n.iteration_bound,
                n.wce,
            ))
        stack.extend(n.children)
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


@cli.command()
@click.option("--no-smoke", is_flag=True, help="Skip the compile-and-run smoke test.")
def doctor(no_smoke: bool):
    """Check installation: toolchain, config, and an end-to-end smoke test."""
    from rich.console import Console
    from hookz.cli.doctor import run_doctor

    sys.exit(run_doctor(Console(), smoke=not no_smoke))


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
@click.option("--pipeline", "pipeline_name", default=None,
              help="Local build toolchain to use (default: local-structural). See `hookz pipelines`.")
@click.option("--buildbox", "--build-box", "use_buildbox", is_flag=True,
              help="Compile through hook-buildbox.xrpl.org; never falls back locally.")
@click.option("--buildbox-url", default=None, hidden=True,
              help="Override the buildbox endpoint (or HOOKZ_BUILDBOX_URL).")
@click.option("--buildbox-options", default="-O3", show_default=True,
              help="Compiler options sent to the buildbox.")
@click.option("--explain", is_flag=True,
              help="Print size/depth/WCE after every stage.")
@waiver_options
def build(source, output, coverage, pipeline_name, use_buildbox, buildbox_url,
          buildbox_options, explain, ignore_depth, ignore_wce_overage,
          ignore_guard_calls, depth32):
    """Compile, clean, and guard-check a hook.

    SOURCE can be a file path or '-' for stdin. Output goes to stdout
    by default when reading from stdin, or to SOURCE.wasm for files.
    """
    import os
    import tempfile
    from hookz.config import load_config

    if os.environ.get("HOOKZ_NO_COVERAGE"):
        coverage = False
    if os.environ.get("HOOKZ_BUILDBOX") == "1":
        use_buildbox = True

    if use_buildbox and coverage:
        raise click.UsageError(
            "--buildbox produces canonical deployable WASM and cannot be "
            "combined with --coverage")
    if use_buildbox and pipeline_name:
        raise click.UsageError(
            "--buildbox selects the remote compiler and cannot be combined "
            "with the local --pipeline option")
    if buildbox_url and not use_buildbox:
        raise click.UsageError("--buildbox-url requires --buildbox")

    ignore = _waivers(ignore_depth, ignore_wce_overage, ignore_guard_calls)
    rules = _rules(depth32)

    if source == "-":
        stdin_data = sys.stdin.buffer.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".c", delete=False)
        tmp.write(stdin_data)
        tmp.close()
        source = Path(tmp.name)
        request_filename = "stdin.c"
        stdout_mode = output is None
    else:
        source = Path(source)
        request_filename = source.name
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

    if use_buildbox:
        _build_buildbox(
            source, output, stdout_mode, ignore, rules,
            endpoint=buildbox_url, options=buildbox_options,
            request_filename=request_filename,
        )
    elif coverage:
        _build_coverage(source, output, config, stdout_mode, ignore, rules)
    else:
        _build_normal(source, output, config, stdout_mode, ignore, rules,
                      pipeline_name=pipeline_name, explain=explain)


@cli.command()
def pipelines():
    """List the build toolchains `hookz build --pipeline` accepts.

    Which flags run decides whether xahaud accepts the binary, so each
    toolchain records where its flags came from.
    """
    from rich.console import Console
    from hookz.wasm.pipeline import (
        BUILD_PIPELINES,
        DEFAULT_PIPELINE,
        PIPELINE_MISNOMERS,
    )

    console = Console()
    for name, p in BUILD_PIPELINES.items():
        mark = "  (default)" if p is DEFAULT_PIPELINE else ""
        console.print(f"[bold]{name}[/bold]{mark}")
        console.print(f"  {p.summary}")
        console.print(f"  [dim]source:[/dim] {p.provenance}")
        console.print(
            f"  [dim]clang[/dim] {p.compile.opt_level}"
            + (" --export-all" if p.compile.export_all else "")
            + f"  [dim]→ wasm-opt[/dim] {p.opt.name}"
            + ("  [dim]→ cleaner[/dim]" if p.clean else "")
        )
        console.print()
    # Named here because it used to be accepted. Someone who learned the old
    # spelling should be told it is gone, not left to read "unknown pipeline"
    # and wonder whether the service went away with it.
    for name in PIPELINE_MISNOMERS:
        console.print(
            f"[dim]rejected:[/dim] {name} [dim]— builds locally, so it is not "
            "a name this flag will take. Use[/dim] --buildbox [dim]for the "
            "service or[/dim] --pipeline local-structural [dim]for the local "
            "approximation.[/dim]"
        )


def _build_fail(log, output, stdout_mode: bool, message: str) -> None:
    """Report a build-stage failure and exit without writing an artifact.

    Nothing is written on failure, so a pre-existing file at `output` is a
    leftover from an earlier build — same path, stale contents, and easy to
    deploy by mistake. Say so rather than letting it pass for current.
    """
    log(f"  {message}")
    # is_file() not exists(): `-o /dev/null` is a device, not a stale artifact.
    if not stdout_mode and output is not None and Path(output).is_file():
        log(f"  NOTE: {output} still holds the previous build — it is now stale.")
    sys.exit(1)


def _build_normal(source: Path, output, config, stdout_mode: bool = False,
                  ignore: frozenset[str] = frozenset(),
                  rules_version: int | None = None,
                  pipeline_name: str | None = None,
                  explain: bool = False) -> None:
    """Standard production build pipeline."""
    from hookz.wasm.clean import CleanError
    from hookz.wasm.guard import validate_guards, GuardError, GUARD_RULE_FIX_20250131
    from hookz.wasm.optimize import WasmOptError
    from hookz.wasm.pipeline import run_pipeline, get_pipeline

    if rules_version is None:
        rules_version = GUARD_RULE_FIX_20250131

    # Status messages go to stderr so stdout is clean for binary output
    log = print if not stdout_mode else lambda *a, **k: print(*a, file=sys.stderr, **k)

    try:
        pipeline = get_pipeline(pipeline_name) if pipeline_name else None
    except ValueError as e:
        _build_fail(log, output, stdout_mode, str(e))

    # Build through the named toolchain. Nothing is written to `output` until
    # every stage has passed — a later stage can still fail, and an unclean
    # binary sitting at the output path looks deployable but is not (xahaud
    # rejects custom sections).
    try:
        trace = run_pipeline(source, pipeline, config)
    except WasmOptError as e:
        # Not skippable. Dropping the optimizer changes block nesting, so a
        # build without it reports a depth this toolchain would never deploy.
        _build_fail(log, output, stdout_mode, f"Optimize FAILED: {e}")
    except CleanError as e:
        _build_fail(log, output, stdout_mode, f"Clean FAILED: {e}")

    cleaned = trace.wasm
    log(f"Built {source.name} via '{trace.pipeline.name}' pipeline "
        f"({trace.pipeline.summary})")
    if explain:
        log(
            "\n".join(
                "  " + line for line in trace.format_table().splitlines()
            )
        )
    else:
        log(f"  {trace.final.size:,} bytes, block depth {trace.final.depth}")

    # 4. Guard check
    try:
        result = validate_guards(cleaned, rules_version=rules_version, ignore=ignore)
        hook_pct = result.hook_wce / 65535 * 100
        verdict = "completed WITH WAIVERS" if result.waived else "PASSED"
        log(f"  Guard check {verdict} (hook WCE={result.hook_wce:,} — {hook_pct:.1f}% of budget)")
    except GuardError as e:
        _build_fail(log, output, stdout_mode, f"Guard check FAILED: {e}")

    # 5. Sanity check
    _validate_wasm(cleaned, source.name, log)

    # Write output
    if stdout_mode:
        sys.stdout.buffer.write(cleaned)
    else:
        output.write_bytes(cleaned)
        log(f"  → {output} ({len(cleaned)} bytes)")
    _report_waived(result, log)
    # Non-zero on waivers: this binary is for analysis, and CI that treats
    # `hookz build` as a deployability gate must not go green on it.
    sys.exit(1 if result.waived else 0)


def _build_buildbox(
    source: Path,
    output,
    stdout_mode: bool = False,
    ignore: frozenset[str] = frozenset(),
    rules_version: int | None = None,
    *,
    endpoint: str | None = None,
    options: str = "-O3",
    request_filename: str | None = None,
) -> None:
    """Canonical remote build followed by independent local validation."""
    from hookz.buildbox import BuildboxError, compile_source
    from hookz.wasm.guard import (
        GUARD_RULE_FIX_20250131,
        GuardError,
        validate_guards,
    )

    if rules_version is None:
        rules_version = GUARD_RULE_FIX_20250131

    log = (
        print
        if not stdout_mode
        else lambda *a, **k: print(*a, file=sys.stderr, **k)
    )

    try:
        result = compile_source(
            source.read_text(),
            filename=request_filename or source.name,
            endpoint=endpoint,
            options=options,
        )
    except BuildboxError as exc:
        _build_fail(log, output, stdout_mode, f"Buildbox FAILED: {exc}")

    wasm = result.wasm
    log(f"Built {source.name} via canonical buildbox")
    log(f"  endpoint: {result.endpoint}")
    log(f"  request sha256: {result.request_sha256}")
    log(f"  source sha256: {result.source_sha256}")
    log(f"  wasm sha256: {result.wasm_sha256}")
    log(f"  attempts: {result.attempts}, bytes: {len(wasm):,}")

    # The service guard-checks the artifact, but a remote success is not
    # authority over the local consumer. Validate the exact returned bytes
    # independently before allowing them to reach the output path.
    try:
        validation = validate_guards(
            wasm, rules_version=rules_version, ignore=ignore
        )
        verdict = "completed WITH WAIVERS" if validation.waived else "PASSED"
        log(
            f"  Local guard check {verdict} "
            f"(hook WCE={validation.hook_wce:,})"
        )
    except GuardError as exc:
        _build_fail(
            log, output, stdout_mode, f"Local guard check FAILED: {exc}"
        )

    _validate_wasm(wasm, source.name, log)
    if stdout_mode:
        sys.stdout.buffer.write(wasm)
    else:
        output.write_bytes(wasm)
        log(f"  → {output} ({len(wasm)} bytes)")
    _report_waived(validation, log)
    sys.exit(1 if validation.waived else 0)


def _build_coverage(source: Path, output, config, stdout_mode: bool = False,
                    ignore: frozenset[str] = frozenset(),
                    rules_version: int | None = None) -> None:
    """Coverage-instrumented build pipeline.

    Pipeline: two-stage compile (DWARF) → instrument → clean → guard-check
    """
    from hookz.compiler import compile_hook_two_stage
    from hookz.coverage.rewriter import instrument_wasm
    from hookz.wasm.clean import clean_hook, CleanError
    from hookz.wasm.guard import validate_guards, GuardError, GUARD_RULE_FIX_20250131
    from hookz.wasm.whitelist import get_import_signatures

    if rules_version is None:
        rules_version = GUARD_RULE_FIX_20250131

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
        _build_fail(log, output, stdout_mode, f"Clean FAILED: {e}")

    # 4. Guard check with __on_source_line in the whitelist
    try:
        coverage_whitelist = get_import_signatures(coverage=True)
        result = validate_guards(
            cleaned, import_whitelist=coverage_whitelist,
            rules_version=rules_version, ignore=ignore,
        )
        hook_pct = result.hook_wce / 65535 * 100
        verdict = "completed WITH WAIVERS" if result.waived else "PASSED"
        log(f"  Guard check {verdict} (hook WCE={result.hook_wce:,} — {hook_pct:.1f}% of budget)")
    except GuardError as e:
        _build_fail(log, output, stdout_mode, f"Guard check FAILED: {e}")

    # 5. Sanity check
    _validate_wasm(cleaned, source.name, log)

    # Write output
    if stdout_mode:
        sys.stdout.buffer.write(cleaned)
    else:
        output.write_bytes(cleaned)
        log(f"  → {output} ({len(cleaned)} bytes, coverage-instrumented)")
    _report_waived(result, log)
    sys.exit(1 if result.waived else 0)


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
@waiver_options
def guard_check(hook_wasm, ignore_depth, ignore_wce_overage,
                ignore_guard_calls, depth32):
    """Validate guard calls in a hook WASM binary."""
    from hookz.wasm.guard import validate_guards, GuardError

    source = Path(hook_wasm)
    wasm = source.read_bytes()
    ignore = _waivers(ignore_depth, ignore_wce_overage, ignore_guard_calls)

    try:
        result = validate_guards(wasm, rules_version=_rules(depth32), ignore=ignore)
    except GuardError as e:
        print(f"Guard check FAILED: {e}")
        if e.codesec >= 0:
            print(f"  Code section: {e.codesec}, byte offset: {e.offset}")
        # Only suggest a waiver for a limit that actually has one. Structural
        # failures cannot be waived, and offering a flag there sends the user
        # looking for an option that will not help.
        if e.key and e.key not in ignore:
            print(f"  (--ignore-{e.key} continues past this to reveal the next problem)")
        sys.exit(1)

    if result.waived:
        print(f"Guard check completed WITH WAIVERS: {source.name}")
    else:
        print(f"Guard check PASSED: {source.name}")
    _print_guard_result(result)
    _report_waived(result)
    sys.exit(1 if result.waived else 0)


@cli.command()
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--source", "-s", "show_source", is_flag=True,
    help="Append a secondary DWARF analysis-twin source view (not artifact WCE).",
)
@click.option(
    "--loops", "show_loops", is_flag=True,
    help="Show partial guard-line loop mapping; subtree rows overlap.",
)
@click.option(
    "--pipeline", "pipeline_name", default=None,
    help="Local production-like pipeline for C input (default: local-structural).",
)
@click.option(
    "--buildbox", "--build-box", "use_buildbox", is_flag=True,
    help="Compile C through hook-buildbox.xrpl.org, then weigh its exact result.",
)
@click.option("--buildbox-url", default=None, hidden=True)
@click.option("--buildbox-options", default="-O3", show_default=True)
@waiver_options
def wce(input_path, show_source, show_loops, pipeline_name, use_buildbox,
        buildbox_url, buildbox_options, ignore_depth, ignore_wce_overage,
        ignore_guard_calls, depth32):
    """Weigh exact WASM, or build C production-style and weigh the result.

    WCE belongs to the final WASM artifact. Source/DWARF mapping is a separate,
    explicitly secondary view because the mapping build can have a radically
    different control-flow tree.

    The deployability verdict is given under the rules the network is actually
    running, which is why it names them.
    """
    import hashlib
    import os

    from rich.console import Console
    from hookz.config import load_config
    from hookz.wasm.guard import GuardError, analyze_wce, validate_guards

    console = Console()
    source: Path | None = input_path if input_path.suffix.lower() == ".c" else None
    is_wasm = input_path.suffix.lower() == ".wasm"

    # An explicitly typed flag beats an environment default, and the mutual
    # exclusion is between two things the *user* asked for. CI sets the switch
    # once for a whole job: it must not make --pipeline unusable inside that
    # job, nor blame a flag nobody typed. A .wasm has already been compiled, so
    # compiler selection does not apply to it either.
    if use_buildbox and pipeline_name:
        raise click.UsageError(
            "--buildbox selects the remote compiler and cannot be combined "
            "with --pipeline"
        )
    if (
        os.environ.get("HOOKZ_BUILDBOX") == "1"
        and not is_wasm
        and not pipeline_name
    ):
        use_buildbox = True
    if buildbox_url and not use_buildbox:
        raise click.UsageError("--buildbox-url requires --buildbox")
    if not is_wasm and source is None:
        raise click.UsageError("INPUT_PATH must end in .c or .wasm")
    if is_wasm and (use_buildbox or pipeline_name):
        raise click.UsageError(
            "a .wasm input is already the artifact; compiler selection only "
            "applies to .c input"
        )
    if is_wasm and show_source:
        raise click.UsageError(
            "a standalone .wasm has no verified source twin; exact guard-line "
            "ids remain visible without --source"
        )

    trace = None
    analysis_config = None
    # A guard id is a __LINE__ from whatever file clang saw. Only a build that
    # strips annotations first emits published line numbers, so only those can
    # be located back in the annotated source — see hookz.annotations.line_map,
    # which exists because the two numberings differ by hundreds of lines and
    # neither says which file it belongs to.
    stripped_before_compile = False
    if is_wasm:
        wasm = input_path.read_bytes()
        if not wasm.startswith(WASM_MAGIC + WASM_VERSION):
            raise click.ClickException(f"{input_path} is not a WebAssembly 1 module")
        provenance = f"provided artifact: {input_path}"
    elif use_buildbox:
        from hookz.buildbox import BuildboxError, compile_source

        try:
            remote = compile_source(
                source.read_text(),
                filename=source.name,
                endpoint=buildbox_url,
                options=buildbox_options,
            )
        except BuildboxError as exc:
            raise click.ClickException(f"buildbox failed: {exc}") from exc
        wasm = remote.wasm
        provenance = (
            f"canonical buildbox result: {remote.endpoint}; "
            f"request {remote.request_sha256}"
        )
        analysis_config = load_config(source_file=source)
        stripped_before_compile = True  # buildbox strips before it sends
    else:
        from hookz.wasm.clean import CleanError
        from hookz.wasm.optimize import WasmOptError
        from hookz.wasm.pipeline import (
            STRIP_ANNOTATIONS, get_pipeline, run_pipeline,
        )

        # Resolved before the try below, because a name this flag will not take
        # is a usage error and nothing has run yet — folding it in reports a
        # rejected spelling as "local pipeline failed", which describes a build
        # that never started.
        try:
            pipeline = get_pipeline(pipeline_name) if pipeline_name else None
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc

        try:
            analysis_config = load_config(source_file=source)
            trace = run_pipeline(source, pipeline, analysis_config)
        except (ValueError, CleanError, WasmOptError, RuntimeError) as exc:
            # RuntimeError is what compile_hook raises when clang fails, which
            # is the most ordinary way for this command to fail at all.
            raise click.ClickException(f"local pipeline failed: {exc}") from exc
        wasm = trace.wasm
        # TODO(guard-line-citation-provenance): membership, where the property
        # actually required is "the artifact's numbering IS strip(source)'s
        # numbering". A pipeline declaring the stripper *and* a line-shifting
        # transform would set this and then map through a map that no longer
        # describes the compiled file. No such transform exists in-tree;
        # _resolve_transform imports any module:function, so the set is
        # open-ended. Fix by building the map from the text run_pipeline
        # actually compiled, which removes the need for this gate.
        stripped_before_compile = STRIP_ANNOTATIONS in trace.pipeline.transforms
        # Read the caveat off the pipeline rather than asserting one. Only
        # local-structural aims at the production compiler; calling the debug
        # pipeline a "production-like approximation" in the same sentence as
        # its own "for reading, not deploying" is the label-over-the-numbers
        # mistake this command was rewritten to stop making.
        caveat = (
            "production-like approximation, not buildbox provenance"
            if trace.pipeline.targets_production
            else "an analysis build — NOT what you would deploy"
        )
        provenance = (
            f"local '{trace.pipeline.name}' result: {trace.pipeline.summary}; "
            f"{caveat}"
        )

    rules = _rules(depth32)
    ignore = _waivers(ignore_depth, ignore_wce_overage, ignore_guard_calls)

    digest = hashlib.sha256(wasm).hexdigest()
    try:
        result = validate_guards(wasm, rules_version=rules, ignore=ignore)
        rejected = None
    except GuardError as exc:
        # Keep the exact artifact report useful after a failed deployability
        # verdict. Best-effort totals can be understated at excessive depth,
        # so the rejection remains the headline.
        result = analyze_wce(wasm, rules_version=rules)
        rejected = str(exc)

    from hookz.wasm.guard import nesting_limit

    console.print()
    console.print(f"[bold]{input_path.name}[/bold] — exact-artifact WCE")
    console.print(f"  [dim]sha256:[/dim] {digest}")
    console.print(f"  [dim]bytes:[/dim] {len(wasm):,}")
    console.print(f"  [dim]provenance:[/dim] {provenance}")
    # A verdict is only meaningful under stated rules. These come from the
    # network's amendment manifest, not from a constant.
    console.print(
        f"  [dim]rules:[/dim] 0x{rules:02X} "
        f"(nesting limit {nesting_limit(rules)})"
        + (" [yellow]--depth32 assumed[/yellow]" if depth32 else "")
    )
    if trace is not None:
        console.print()
        console.print(trace.format_table())
    console.print()
    if rejected is None:
        console.print("  [bold green]DEPLOYABILITY: PASSED[/bold green]")
    else:
        console.print("  [bold red]DEPLOYABILITY: REJECTED[/bold red]")
        console.print(f"  [red]{rejected}[/red]")
        if result.nesting_exceeded:
            console.print(
                "  [red]WCE below is a floor because over-depth blocks are "
                "not counted.[/red]"
            )
    console.print()

    line_map = (
        _annotated_line_map(source)
        if show_loops and source is not None and stripped_before_compile
        else None
    )

    max_wce = 65535
    # An entry point that is not exported has no cost, and "WCE: 0 / 65,535
    # (0.0%)" reads as one that costs nothing rather than one that is absent.
    # hook() missing is a rejection in its own right and already reported as
    # an error above; cbak() missing is ordinary.
    present = (
        ("hook()", result.hook_wce, result.hook_tree, result.hook_func_idx >= 0),
        ("cbak()", result.cbak_wce, result.cbak_tree,
         result.cbak_func_idx is not None),
    )
    for label, exact_wce, tree, exported in present:
        if not exported:
            console.print(f"  [bold]{label}[/bold] [dim]not exported[/dim]")
            console.print()
            continue
        pct = exact_wce / max_wce * 100
        console.print(
            f"  [bold]{label}[/bold] WCE: {exact_wce:,} / {max_wce:,} "
            f"({pct:.1f}%)"
        )
        loops = (
            _collect_loops(tree, line_map)
            if show_loops and tree is not None
            else []
        )
        if loops:
            console.print(
                "    [yellow]partial mapping:[/yellow] guard ids identify "
                "source lines, but loop subtree costs overlap and are not "
                "additive"
            )
            for loc, bound, loop_wce in sorted(
                loops, key=lambda item: item[2], reverse=True
            ):
                console.print(
                    f"    {loc:>20s}  GUARD({bound:<5d})  "
                    f"subtree WCE {loop_wce:>7,}"
                )
        console.print()

    if result.errors:
        console.print(f"  [yellow]⚠ {len(result.errors)} warning(s):[/yellow]")
        for err in result.errors:
            console.print(f"    [dim]{err}[/dim]")
        console.print()

    if show_source and source is not None:
        from hookz.compiler import compile_hook, compile_hook_two_stage
        from hookz.coverage.rewriter import parse_dwarf_locations
        from hookz.wasm.clean import clean_hook_detailed
        from hookz.wasm.visitor import KeepDebugVisitor

        dwarf_locs = []
        debug_dwarf_locs = []
        try:
            twin = compile_hook_two_stage(
                source, analysis_config, opt_level="-Oz"
            )
            twin = clean_hook_detailed(
                twin, visitor=KeepDebugVisitor()
            ).wasm
            dwarf_locs = parse_dwarf_locations(twin)
            twin_result = analyze_wce(twin)
            debug = compile_hook(
                source, config=analysis_config, debug=True, optimize=False
            )
            debug = clean_hook_detailed(
                debug, visitor=KeepDebugVisitor()
            ).wasm
            debug_dwarf_locs = parse_dwarf_locations(debug)
        except Exception as exc:
            console.print(
                f"[yellow]secondary source view unavailable: {exc}[/yellow]"
            )
        else:
            _print_annotated_source(
                console, source, dwarf_locs, debug_dwarf_locs, twin_result
            )

    sys.exit(1 if rejected is not None else 0)


@cli.command("build-test-hooks")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", default=None, help="Output header path (default: auto from input name).")
@click.option("--symbol", default=None, help="C++ symbol name for the map (default: auto from input name).")
@click.option("-j", "--jobs", type=int, default=0, help="Parallel workers (default: CPU count).")
@click.option("--force-write", is_flag=True, help="Always write output even if unchanged.")
@click.option("--hooks-c-dir", "hooks_c_dir_raw", multiple=True,
              help="Hook source dirs as domain=path (e.g. tipbot=~/hooks). Repeatable.")
@click.option("--hook-coverage/--no-hook-coverage", default=False,
              help="Compile with coverage instrumentation.")
@click.option("--no-cache", is_flag=True, help="Bypass compilation cache.")
@click.option("--compiler", type=click.Choice(["hookz", "wasmcc", "buildbox"], case_sensitive=False),
              default=None, help="Compiler backend (default: wasmcc for SetHook_test, hookz otherwise).")
@click.option("--buildbox", "--build-box", "use_buildbox", is_flag=True,
              help="Compile C blocks through the canonical service; no local fallback.")
@click.option("--buildbox-url", default=None, hidden=True,
              help="Override the buildbox endpoint (or HOOKZ_BUILDBOX_URL).")
@click.option("--buildbox-options", default="-O3", show_default=True,
              help="Compiler options sent to the buildbox.")
def build_test_hooks(input_file, output, symbol, jobs, force_write,
                     hooks_c_dir_raw, hook_coverage, no_cache, compiler,
                     use_buildbox, buildbox_url, buildbox_options):
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
    if os.environ.get("HOOKZ_BUILDBOX") == "1":
        use_buildbox = True

    if use_buildbox and compiler not in (None, "buildbox"):
        raise click.UsageError(
            "--buildbox cannot be combined with a different --compiler")
    if buildbox_url and not (use_buildbox or compiler == "buildbox"):
        raise click.UsageError("--buildbox-url requires --buildbox")
    if use_buildbox:
        compiler = "buildbox"
    if compiler == "buildbox" and hook_coverage:
        raise click.UsageError(
            "--buildbox produces canonical deployable WASM and cannot be "
            "combined with --hook-coverage")

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
        # Default compiler: wasmcc for SetHook_test (exact compat), hookz otherwise
        if compiler is None:
            compiler = "wasmcc" if input_file.stem == "SetHook_test" else "hookz"

        if compiler == "wasmcc" and hook_coverage:
            # wasmcc doesn't support coverage — force hookz
            compiler = "hookz"

        builder = TestHookBuilder(
            input_file=input_file,
            jobs=jobs,
            force_write=force_write,
            hooks_c_dirs=hooks_c_dirs or None,
            coverage=hook_coverage,
            no_cache=no_cache,
            output_file=Path(output) if output else None,
            symbol_name=symbol,
            compiler=compiler,
            buildbox_endpoint=buildbox_url,
            buildbox_options=buildbox_options,
        )
        builder.build()
    except RuntimeError as e:
        print(f"Build failed: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point — referenced in pyproject.toml [project.scripts]
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("source", type=click.Path(exists=True))
@click.option("--all", "show_all", is_flag=True,
              help="Include arithmetic, tracing and exit calls.")
@click.option("--source", "show_source", is_flag=True,
              help="Show the construct each call sits in.")
def surface(source, show_all, show_source):
    """What a hook does to the ledger, read out of its binary.

    Every host-API call the compiled hook contains, with the constants the
    source hid behind macros resolved, attributed back to the line it came
    from. The C tools cannot see through `sfRewardTime` or a `#define`d
    offset; the binary has the number.
    """
    from rich.console import Console

    from hookz.citations import render, span_for
    from hookz.compiler import compile_hook
    from hookz.config import load_config
    from hookz.coverage.rewriter import instrument_wasm
    from hookz.wasm.dataflow import calls_by_source_line

    console = Console()
    src = Path(source)
    config = load_config(source_file=src)

    import tempfile
    wasm = compile_hook(src, config=config)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    try:
        tmp.write(wasm)
        tmp.close()
        instrumented, _locs = instrument_wasm(wasm, tmp.name)
    finally:
        Path(tmp.name).unlink(missing_ok=True)

    calls = calls_by_source_line(instrumented)
    if not calls:
        console.print("[red]no instrumentation — nothing to attribute[/red]")
        return 1
    if not show_all:
        calls = [(ln, c) for ln, c in calls if c.name not in _PLUMBING]

    console.print(f"\n[bold]{src.name}[/bold] — {len(calls)} ledger interaction(s)\n")
    for line, call in calls:
        args = ", ".join(_pretty(a, call.name, i)
                         for i, a in enumerate(call.args))
        console.print(f"  [dim]{line:>5}[/dim]  {call.name}({args})")
        if show_source:
            # Text, not markup: render() returns C, and emits its own
            # [node_type] tag. See _plain_panel in hookz.testing.plugin.
            from rich.text import Text

            console.print(
                Text(render(span_for(src, line), max_lines=12), style="dim")
            )
            console.print()
    return 0


@cli.command()
@click.argument("pattern")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--xahaud", is_flag=True,
              help="Search the configured xahaud checkout instead of PATHS.")
@click.option("--glob", "globs", multiple=True, metavar="GLOB",
              help="Restrict to files matching (repeatable). "
                   "Default: *.c *.h *.cpp *.ipp")
@click.option("-n", "--max-hits", default=40, show_default=True,
              help="Stop after this many matching lines.")
@click.option("-L", "--max-lines", default=24, show_default=True,
              help="Abridge a construct longer than this.")
@click.option("--names", is_flag=True,
              help="List the enclosing symbols only, without source.")
def cite(pattern, paths, xahaud, globs, max_hits, max_lines, names):
    """Grep that returns constructs instead of lines.

    A grep hit is a line, and a line is usually not the claim — it is the
    middle of one. Every hit here is widened to the construct that owns it (the
    function, the `if`, the declaration) with tree-sitter, and hits that land
    in the same construct collapse into one block naming all of them.

    So `hookz cite 'temMALFORMED' --xahaud` answers "where is this rejected,
    and under what condition" rather than handing back forty middles.
    """
    import re

    from rich.console import Console

    from hookz.citations import merge, render, span_for

    console = Console()
    roots = [Path(p) for p in paths]
    if xahaud:
        from hookz.config import load_config
        roots.append(Path(load_config().xahaud_root) / "src")
    if not roots:
        roots = [Path.cwd()]

    suffixes = tuple(globs) or ("*.c", "*.h", "*.cpp", "*.ipp")
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        console.print(f"[red]bad pattern: {exc}[/red]")
        raise SystemExit(2)

    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
            continue
        for pat in suffixes:
            files.extend(sorted(root.rglob(pat)))

    spans, hits, truncated = [], 0, False
    for path in files:
        try:
            text = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(text, 1):
            if not rx.search(line):
                continue
            hits += 1
            if hits > max_hits:
                truncated = True
                break
            spans.append(span_for(path, number))
        if truncated:
            break

    # A regex is not markup, and it is not escapable markup either: `[0-9]`
    # gets eaten as a tag, and escaping it only trades that for `\[` losing its
    # backslash. Both misquote the search the command just ran. Text is
    # literal; the styling goes on a span.
    from rich.markup import escape
    from rich.text import Text

    def _pattern_line(suffix: str, style: str = "") -> Text:
        line = Text(style=style)
        line.append(f"/{pattern}/", style="bold" if not style else style)
        line.append(suffix)
        return line

    if not spans:
        console.print(
            _pattern_line(f" — no match in {len(files)} file(s)", style="dim")
        )
        raise SystemExit(1)

    blocks = _by_symbol(merge(spans))
    console.print()
    console.print(
        _pattern_line(f" — {hits} hit(s) in {len(blocks)} construct(s)")
    )
    console.print()
    for span in blocks:
        if names:
            where = span.symbol or span.node_type
            console.print(f"  [dim]{Path(span.path).name}:{span.start}[/dim]"
                          f"  {escape(where)}  [dim]({len(span.lines)} hit(s))[/dim]")
        else:
            # render() returns C source and emits its own [node_type] tag —
            # both literal. This is the command whose entire job is quoting
            # source back accurately.
            console.print(Text(render(span, max_lines=max_lines)))
            console.print()

    if truncated:
        console.print(f"[yellow]stopped at {max_hits} hits — "
                      f"narrow the pattern or raise -n[/yellow]")
    return 0


def _by_symbol(spans):
    """Fold constructs that share an enclosing function into one block.

    `merge` folds spans that physically overlap, which is right for citations
    but too narrow for a search: two `return`s in one function are two disjoint
    statements, so they survive as two excerpts of the same function with the
    marker in a different place. Grouping by symbol gives the answer a reader
    wants — this function, these lines in it — and `render` abridges the middle
    so a wide span stays readable.

    Spans with no enclosing symbol (file-scope declarations, macros) are left
    exactly as `merge` produced them.
    """
    from hookz.citations import Span

    grouped: dict[tuple[str, str], Span] = {}
    out: list[Span] = []
    for span in spans:
        if span.symbol is None:
            out.append(span)
            continue
        key = (span.path, span.symbol)
        first = grouped.get(key)
        if first is None:
            grouped[key] = span
            out.append(span)
            continue
        first.start = min(first.start, span.start)
        first.end = max(first.end, span.end)
        first.lines = sorted(set(first.lines) | set(span.lines))
    return out


# Calls that say nothing about a hook's relationship with the ledger.
_PLUMBING = frozenset({
    "_g", "trace", "trace_num", "trace_float", "trace_slot", "accept",
    "rollback", "float_set", "float_int", "float_multiply", "float_divide",
    "float_compare", "float_sum", "float_sto", "float_mulratio", "float_negate",
    "util_raddr", "util_accid", "util_sha512h", "otxn_type", "otxn_id",
    "hookz_dev_u64", "hookz_dev_str", "hookz_dev_check", "__on_source_line",
})


def _pretty(arg, api: str | None = None, position: int | None = None) -> str:
    """A resolved constant, named only where the name is certain.

    A trailing `*` marks a value inferred from a single-assignment local rather
    than read off the stack at the call — different strengths of evidence, kept
    visible.
    """
    from hookz.wasm.dataflow import Const, ConstFromLocal

    if not isinstance(arg, (Const, ConstFromLocal)):
        return "?"
    mark = "" if isinstance(arg, Const) else "*"
    return f"{_name_for(arg.value, api, position) or arg.value}{mark}"


# Where a small integer means something other than itself. Naming by value
# alone is how `hook_account(buf, 20)` becomes `hook_account(buf,
# KEYLET_ESCROW)` — the constant really is 20, and the reading is nonsense.
# A keylet type is only a keylet type in the argument that takes one.
_KEYLET_TYPE_ARG = {"util_keylet": 2}


def _name_for(value: int, api: str | None = None,
              position: int | None = None) -> str | None:
    """A name for a constant, only where the position makes it unambiguous.

    Field ids are safe on value alone: an sfCode is `type << 16 | field`, far
    outside the range of a length or a slot number. Keylet types are not — they
    are small integers that collide with every buffer size in the API — so they
    are named only in the argument that takes one.
    """
    from hookz import hookapi

    if value > 0xFFFF:
        for key, known in vars(hookapi).items():
            if key.startswith("sf") and known == value:
                return key
        return None

    if api is not None and _KEYLET_TYPE_ARG.get(api) == position:
        for key, known in vars(hookapi).items():
            if key.startswith("KEYLET_") and known == value:
                return key
    return None


def main():
    """Run the CLI, rendering Click's own errors as errors.

    `standalone_mode=False` stops Click catching anything, which also stops it
    printing `UsageError`/`ClickException` — every one of them reached the user
    as a Python traceback with the message on the last line. Rendering them
    here restores that without giving Click back control of exit codes, which
    the commands set themselves via sys.exit.
    """
    try:
        cli(standalone_mode=False)
    except click.exceptions.Abort:
        click.echo("Aborted!", err=True)
        sys.exit(1)
    except click.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    main()
