"""hookz — CLI for the hook testing framework.

Usage:
    hookz test [pytest args...]       Run tests via pytest
    hookz coverage [--threshold N]    Run tests + show uncovered report
    hookz find-tests <file>:<start>-<end>  Find tests that cover a line range
    hookz show <function>             Show hook API function implementation
    hookz show --list                 List all hook API functions + status
    hookz debug-compile <source.c>    Check if a hook compiles (debug build, not for deployment)
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
    }

    if cmd not in commands:
        print(f"Unknown command: {cmd}")
        print(f"Available: {', '.join(commands)}")
        return 1

    return commands[cmd](rest)


if __name__ == "__main__":
    sys.exit(main())
