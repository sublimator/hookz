"""Pytest integration — register_hooks() generates fixtures from a hook map.

Usage in conftest.py:

    from hookz.testing import register_hooks

    register_hooks({
        "tip": "path/to/tip.c",
        "top": "path/to/top.c",
    })

This creates for each hook:
- {name}_hook: session-scoped Hook object (wasm + label + source)
- {name}_wasm: session-scoped alias for raw WASM bytes (compat)
- {name}_coverage: session-scoped CoverageTracker
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from hookz.compiler import compile_hook
from hookz.config import load_config
from hookz.coverage.tracker import CoverageTracker
from hookz.coverage.rewriter import instrument_wasm
from hookz.runtime import Hook, HookRuntime


# Global registry: populated by register_hooks(), read by the plugin
_hook_registry: dict[str, Path] = {}
_coverage_trackers: dict[str, CoverageTracker] = {}


def register_hooks(hooks: dict[str, str | Path], base_dir: Path | None = None):
    """Register hooks for fixture generation.

    Args:
        hooks: mapping of name → source path (e.g. {"tip": "tip.c"})
        base_dir: base directory for relative paths (default: caller's dir)
    """
    if base_dir is None:
        import inspect
        frame = inspect.stack()[1]
        base_dir = Path(frame.filename).parent

    for name, source in hooks.items():
        source = Path(source)
        if not source.is_absolute():
            source = (base_dir / source).resolve()
        _hook_registry[name] = source
        _coverage_trackers[name] = CoverageTracker()

    # Generate the fixtures dynamically
    _generate_fixtures()


_compiled_hooks: dict[str, Hook] = {}


def _compile_once(name: str) -> Hook:
    """Compile and instrument a hook, cached per session."""
    if name not in _compiled_hooks:
        source_path = _hook_registry[name]
        tracker = _coverage_trackers[name]
        config = load_config()
        wasm_bytes = compile_hook(source_path, config=config)

        tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
        tmp.write(wasm_bytes)
        tmp.close()

        instrumented, locs = instrument_wasm(wasm_bytes, tmp.name)
        tracker.set_executable_lines(locs, source_path=source_path)
        _compiled_hooks[name] = Hook(
            wasm=instrumented, label=source_path.name, source=source_path,
        )
    return _compiled_hooks[name]


def _generate_fixtures():
    """Create pytest fixtures for all registered hooks."""
    for name in _hook_registry:
        tracker = _coverage_trackers[name]

        @pytest.fixture(scope="session")
        def _hook_fixture(_name=name):
            return _compile_once(_name)

        @pytest.fixture(scope="session")
        def _wasm_fixture(_name=name):
            return _compile_once(_name).wasm

        @pytest.fixture(scope="session")
        def _coverage_fixture(_trk=tracker):
            return _trk

        _hook_fixture.__name__ = f"{name}_hook"
        _wasm_fixture.__name__ = f"{name}_wasm"
        _coverage_fixture.__name__ = f"{name}_coverage"

        globals()[f"{name}_hook"] = _hook_fixture
        globals()[f"{name}_wasm"] = _wasm_fixture
        globals()[f"{name}_coverage"] = _coverage_fixture



def get_coverage_trackers() -> dict[str, tuple[CoverageTracker, Path]]:
    """Get all registered coverage trackers + source paths."""
    return {
        name: (tracker, _hook_registry[name])
        for name, tracker in _coverage_trackers.items()
    }


# Per-test coverage tracking: test_id → {hook_name → set of lines hit}
_per_test_lines: dict[str, dict[str, set[int]]] = {}
_pre_test_snapshots: dict[str, dict[str, set[int]]] = {}


def _snapshot_hit_counts() -> dict[str, dict[int, int]]:
    """Snapshot current hit counts for all trackers."""
    return {
        name: dict(tracker._line_hits)
        for name, tracker in _coverage_trackers.items()
    }


def pytest_runtest_setup(item):
    """Snapshot coverage before each test, print newline for trace output."""
    import os, sys
    _pre_test_snapshots[item.nodeid] = _snapshot_hit_counts()
    if os.environ.get("HOOKZ_TRACE"):
        sys.stderr.write("\n")
        sys.stderr.flush()


def pytest_runtest_teardown(item, nextitem):
    """Diff hit counts after each test to find lines this test executed."""
    pre = _pre_test_snapshots.pop(item.nodeid, {})
    post = _snapshot_hit_counts()
    diff = {}
    for name in post:
        pre_counts = pre.get(name, {})
        post_counts = post[name]
        hit_lines = {
            ln for ln, count in post_counts.items()
            if count > pre_counts.get(ln, 0)
        }
        if hit_lines:
            diff[name] = hit_lines
    if diff:
        _per_test_lines[item.nodeid] = diff

    # Grab any HookRuntime instances from test's fixtures for future use
    funcargs = getattr(item, "funcargs", None) or {}
    for val in funcargs.values():
        if isinstance(val, HookRuntime):
            # Could stash traces, state snapshots, etc. here
            pass


def find_tests_for_lines(hook_name: str, start: int, end: int) -> list[str]:
    """Find test IDs that hit any line in the given range."""
    results = []
    for test_id, hook_lines in _per_test_lines.items():
        lines = hook_lines.get(hook_name, set())
        if any(start <= ln <= end for ln in lines):
            results.append(test_id)
    return results


def pytest_sessionfinish(session, exitstatus):
    """Print coverage reports for all registered hooks."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    console.print()  # newline after last test result

    for name, (tracker, source_path) in get_coverage_trackers().items():
        if not tracker.lines_hit:
            continue

        src_name = source_path.name
        console.print(Panel(
            tracker.summary(),
            title=f"{src_name} coverage",
            border_style="green" if tracker.coverage_pct() > 80 else "yellow",
        ))

        if tracker.uncovered_lines:
            report = tracker.uncovered_report(source_path, context=1)
            console.print(Panel(
                report,
                title=f"{src_name} — uncovered lines",
                border_style="red",
            ))
        else:
            console.print(f"  {src_name}: 100% coverage!")
        console.print()
