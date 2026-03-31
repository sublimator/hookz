"""hookz — CLI for the hook testing framework.

Usage:
    hookz test [pytest args...]       Run tests via pytest
    hookz coverage [--threshold N]    Run tests + show uncovered report
    hookz find-tests <file>:<start>-<end>  Find tests that cover a line range
    hookz show <function>             Show hook API function implementation
    hookz show --list                 List all hook API functions + status
    hookz debug-compile <source.c>    Check if a hook compiles (debug build, not for deployment)
    hookz build <source.c>            Compile + clean + guard-check (production build)
    hookz clean <hook.wasm>           Clean a WASM binary for deployment
    hookz guard-check <hook.wasm>     Validate guard calls in a WASM binary
    hookz wce <source.c>              Analyze WCE budget usage with source lines
"""

from __future__ import annotations

import sys
from pathlib import Path


def cmd_test(args: list[str]) -> int:
    """Run pytest with hookz config."""
    import pytest
    return pytest.main(args)


def cmd_coverage(args: list[str]) -> int:
    """Run tests and show coverage report."""
    import pytest

    # Inject -v if not present, and add our coverage marker
    if "-v" not in args and "--verbose" not in args:
        args = ["-v"] + args

    result = pytest.main(args)

    # Check threshold
    from hookz.config import load_config
    config = load_config()

    for i, a in enumerate(args):
        if a == "--threshold":
            config.coverage_threshold = int(args[i + 1])

    return result


def cmd_show(args: list[str]) -> int:
    """Show hook API function implementation from xahaud source."""
    from rich.console import Console

    from hookz.config import load_config

    console = Console()
    config = load_config()

    if not args or args[0] == "--list":
        return _show_list(console, config)

    name = args[0]
    return _show_function(console, config, name)


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


def cmd_debug_compile(args: list[str]) -> int:
    """Debug-compile a hook to check it builds. Not for deployment."""
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    if not args:
        print("Usage: hookz debug-compile <source.c> [-o output.wasm]")
        print("  Compiles with debug info (-g -O0) and test flags from hookz.toml.")
        print("  This is for checking compilation, not producing deployable WASM.")
        return 1

    source = Path(args[0])
    output = None

    if len(args) >= 3 and args[1] == "-o":
        output = Path(args[2])

    if output is None:
        output = source.with_suffix(".wasm")

    config = load_config()
    wasm = compile_hook(source, output, config, debug=True, optimize=False)
    print(f"Debug-compiled {source.name} → {output} ({len(wasm)} bytes)")
    return 0


def cmd_find_tests(args: list[str]) -> int:
    """Find tests that cover a given line range.

    Usage: hookz find-tests tip.c:225-400
           hookz find-tests top.c:300
    """
    import re
    import pytest

    if not args:
        print("Usage: hookz find-tests <file>:<start>[-<end>]")
        print("  Example: hookz find-tests tip.c:225-400")
        return 1

    # Parse file:start-end
    m = re.match(r'(\w+\.\w+):(\d+)(?:-(\d+))?$', args[0])
    if not m:
        print(f"Invalid format: {args[0]}")
        print("Expected: <file>:<start>[-<end>]  e.g. tip.c:225-400")
        return 1

    filename = m.group(1)
    start = int(m.group(2))
    end = int(m.group(3)) if m.group(3) else start

    # Run all tests silently to collect per-test coverage
    pytest.main(["-x", "-q", "--tb=no", "--no-header"] + args[1:])

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
        return 1

    tests = find_tests_for_lines(hook_name, start, end)

    if not tests:
        print(f"No tests cover {filename}:{start}-{end}")
    else:
        print(f"\nTests covering {filename}:{start}-{end}:")
        for t in sorted(tests):
            print(f"  {t}")
        print(f"\n{len(tests)} test(s) found")

    return 0


def cmd_clean(args: list[str]) -> int:
    """Clean a hook WASM binary for deployment.

    Usage: hookz clean <input.wasm> [-o output.wasm]
    """
    from hookz.wasm.clean import clean_hook, CleanError

    if not args:
        print("Usage: hookz clean <input.wasm> [-o output.wasm]")
        return 1

    source = Path(args[0])
    output = source  # overwrite by default

    if len(args) >= 3 and args[1] == "-o":
        output = Path(args[2])

    wasm = source.read_bytes()
    try:
        cleaned = clean_hook(wasm)
    except CleanError as e:
        print(f"Clean failed: {e}")
        return 1

    output.write_bytes(cleaned)
    print(f"Cleaned {source.name}: {len(wasm)} → {len(cleaned)} bytes → {output}")
    return 0


def cmd_guard_check(args: list[str]) -> int:
    """Validate guard calls in a hook WASM binary.

    Usage: hookz guard-check <hook.wasm>
    """
    from hookz.wasm.guard import validate_guards, GuardError

    if not args:
        print("Usage: hookz guard-check <hook.wasm>")
        return 1

    source = Path(args[0])
    wasm = source.read_bytes()

    try:
        result = validate_guards(wasm)
    except GuardError as e:
        print(f"Guard check FAILED: {e}")
        if e.codesec >= 0:
            print(f"  Code section: {e.codesec}, byte offset: {e.offset}")
        return 1

    print(f"Guard check PASSED: {source.name}")
    _print_guard_result(result)
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


def cmd_build(args: list[str]) -> int:
    """Compile, clean, and guard-check a hook in one step.

    Usage: hookz build <source.c> [-o output.wasm]
    """
    from hookz.compiler import compile_hook
    from hookz.config import load_config
    from hookz.wasm.clean import clean_hook, CleanError
    from hookz.wasm.guard import validate_guards, GuardError

    if not args:
        print("Usage: hookz build <source.c> [-o output.wasm]")
        return 1

    source = Path(args[0])
    output = source.with_suffix(".wasm")

    if len(args) >= 3 and args[1] == "-o":
        output = Path(args[2])

    config = load_config()

    # 1. Compile
    print(f"Compiling {source.name}...")
    wasm = compile_hook(source, output, config, debug=False, optimize=True)
    print(f"  Compiled: {len(wasm)} bytes")

    # 2. Optimize (if wasm-opt available)
    wasm = _try_optimize(wasm)

    # 3. Clean
    try:
        cleaned = clean_hook(wasm)
        print(f"  Cleaned: {len(wasm)} → {len(cleaned)} bytes")
    except CleanError as e:
        print(f"  Clean FAILED: {e}")
        return 1

    # 4. Guard check
    try:
        result = validate_guards(cleaned)
        hook_pct = result.hook_wce / 65535 * 100
        print(f"  Guard check PASSED (hook WCE={result.hook_wce:,} — {hook_pct:.1f}% of budget)")
    except GuardError as e:
        print(f"  Guard check FAILED: {e}")
        return 1

    # Write output
    output.write_bytes(cleaned)
    print(f"  → {output} ({len(cleaned)} bytes)")
    return 0


def cmd_wce(args: list[str]) -> int:
    """Analyze worst-case execution budget usage with source line mapping.

    Usage: hookz wce <source.c>
    """
    from rich.console import Console
    from hookz.compiler import compile_hook
    from hookz.config import load_config
    from hookz.wasm.guard import GuardError, BlockInfo
    from hookz.coverage.rewriter import parse_dwarf_locations

    if not args:
        print("Usage: hookz wce <source.c>")
        return 1

    console = Console()
    source = Path(args[0])
    config = load_config()

    # Compile with debug info for DWARF
    import tempfile
    wasm_path = Path(tempfile.mktemp(suffix=".wasm"))
    wasm = compile_hook(source, wasm_path, config, debug=True, optimize=False)
    console.print(f"[dim]Compiled {source.name} ({len(wasm)} bytes, debug build)[/dim]")

    # Parse DWARF locations
    try:
        dwarf_locs = parse_dwarf_locations(str(wasm_path))
    except Exception:
        dwarf_locs = []
    finally:
        wasm_path.unlink(missing_ok=True)

    # Build address → source line map
    addr_to_line: dict[int, tuple[str, int]] = {}
    for loc in dwarf_locs:
        addr_to_line[loc.address] = (f"L{loc.line}", loc.line)

    # Clean (rewrite guards, strip sections) then guard-check
    from hookz.wasm.clean import clean_hook, CleanError
    from hookz.wasm.guard import validate_guards

    try:
        cleaned = clean_hook(wasm)
    except CleanError as e:
        console.print(f"[red]Clean failed:[/red] {e}")
        return 1

    try:
        result = validate_guards(cleaned)
    except GuardError as e:
        console.print(f"[red]Guard check failed:[/red] {e}")
        return 1

    max_wce = 65535

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

    def _collect_loops(node: BlockInfo) -> list[tuple[str, int, int]]:
        """Collect all loop nodes with (source_location, bound, wce)."""
        loops = []
        if node.is_loop:
            loc = _line_from_guard_id(node.guard_id)
            loops.append((loc, node.iteration_bound, node.wce))
        for child in node.children:
            loops.extend(_collect_loops(child))
        return loops

    # Print analysis
    console.print()
    console.print(f"[bold]{source.name}[/bold] — Worst-Case Execution Analysis")
    console.print()

    for label, wce, tree in [
        ("hook()", result.hook_wce, result.hook_tree),
        ("cbak()", result.cbak_wce, result.cbak_tree),
    ]:
        if tree is None:
            continue
        pct = wce / max_wce * 100
        bar_filled = int(pct / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        console.print(f"  [bold]{label}[/bold] WCE: {wce:,} / {max_wce:,} ({pct:.1f}%)  {bar}")
        console.print()

        loops = _collect_loops(tree)
        if not loops:
            console.print("    [dim]No loops found[/dim]")
            continue

        loops.sort(key=lambda x: x[2], reverse=True)
        for loc, bound, loop_wce in loops:
            loop_pct = loop_wce / max(wce, 1) * 100
            lbar_filled = int(loop_pct / 5)
            lbar = "█" * lbar_filled + "░" * (20 - lbar_filled)
            console.print(
                f"    {loc:>20s}  GUARD({bound:<5d})  "
                f"{loop_wce:>6,} instrs  {lbar}  {loop_pct:4.1f}%"
            )
        console.print()

    return 0


def _try_optimize(wasm: bytes) -> bytes:
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
        print(f"  ⚠ wasm-opt not found — skipping optimization ({hint})")
        return wasm

    from hookz.wasm.optimize import optimize_hook
    before = len(wasm)
    wasm = optimize_hook(wasm)
    print(f"  Optimized: {before} → {len(wasm)} bytes")
    return wasm


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0

    cmd = args[0]
    rest = args[1:]

    commands = {
        "test": cmd_test,
        "coverage": cmd_coverage,
        "find-tests": cmd_find_tests,
        "show": cmd_show,
        "debug-compile": cmd_debug_compile,
        "clean": cmd_clean,
        "guard-check": cmd_guard_check,
        "build": cmd_build,
        "wce": cmd_wce,
    }

    if cmd not in commands:
        print(f"Unknown command: {cmd}")
        print(f"Available: {', '.join(commands)}")
        return 1

    return commands[cmd](rest)


if __name__ == "__main__":
    sys.exit(main())
