"""Dispatch development hook checkpoints to Lean checks."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class LeanCheckResult:
    tag: str
    lean_file: Path


class DevLeanError(RuntimeError):
    """Raised when a development Lean checkpoint cannot be checked."""


def _lake_binary() -> str | None:
    configured = os.environ.get("LAKE")
    if configured:
        return configured
    found = shutil.which("lake")
    if found:
        return found
    elan_lake = Path.home() / ".elan" / "bin" / "lake"
    if elan_lake.exists():
        return str(elan_lake)
    return None


def lean_available() -> bool:
    return _lake_binary() is not None


def _capture_map(events: list[dict]) -> dict[str, dict]:
    captures: dict[str, dict] = {}
    for event in events:
        kind = event.get("kind")
        if kind in {"u64", "i64", "bytes"}:
            name = event.get("name")
            if isinstance(name, str):
                captures[name] = event
    return captures


def _required_u64(captures: dict[str, dict], name: str) -> int:
    event = captures.get(name)
    if event is None or event.get("kind") != "u64":
        raise DevLeanError(f"missing u64 capture {name!r}")
    value = event.get("value")
    if not isinstance(value, int) or value < 0:
        raise DevLeanError(f"capture {name!r} must be a non-negative integer")
    return value


def _state_counter_after_increment(captures: dict[str, dict]) -> str:
    before = _required_u64(captures, "before_count")
    after = _required_u64(captures, "count")
    return f"""import Hookz.Contracts.StateCounter

open Hookz.Contracts

-- generated from hookz dev checkpoint: state_counter.after_increment
example :
    Hookz.Contracts.StateCounter.expected {{
      txKind := .payment,
      owner := false,
      counterState := some {before},
      counterParam := none
    }} = {{ verdict := .accept, counterState := some {after} }} := by
  native_decide
"""


_ADAPTERS: dict[str, Callable[[dict[str, dict]], str]] = {
    "state_counter.after_increment": _state_counter_after_increment,
}


def render_dev_lean_checks(events: list[dict]) -> list[tuple[str, str]]:
    """Render Lean snippets for all `check` events in a dev event stream.

    Captures before a `check` event are consumed by that check. `hookz_dev_check`
    calls this during hook execution, so the directive acts like a point-in-time
    assertion rather than a post-run trace.
    """
    rendered: list[tuple[str, str]] = []
    pending: list[dict] = []
    for event in events:
        kind = event.get("kind")
        if kind == "check":
            tag = event.get("tag")
            if not isinstance(tag, str):
                raise DevLeanError(f"invalid check event tag: {event!r}")
            adapter = _ADAPTERS.get(tag)
            if adapter is None:
                raise DevLeanError(f"no Lean dev adapter registered for {tag!r}")
            rendered.append((tag, adapter(_capture_map(pending))))
            pending = []
        else:
            pending.append(event)
    return rendered


def dispatch_dev_lean_checks(
    events: list[dict],
    out_dir: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> list[LeanCheckResult]:
    """Generate and check Lean files for recorded development hook events."""
    lake = _lake_binary()
    if lake is None:
        raise DevLeanError("lake not found; install Lean or set LAKE")

    if out_dir is None:
        out_dir = Path(os.environ.get("HOOKZ_LEAN_DEV_DIR", "/tmp/hookz-lean-dev-checks"))
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[LeanCheckResult] = []
    for index, (tag, lean_source) in enumerate(render_dev_lean_checks(events), 1):
        slug = tag.replace(".", "_").replace("-", "_")
        lean_file = out_dir / f"{index:03d}_{slug}.lean"
        lean_file.write_text(lean_source)

        cmd = [lake, "env", "lean", str(lean_file)]
        checked = subprocess.run(cmd, cwd=project_root, capture_output=True, text=True)
        if checked.returncode != 0:
            raise DevLeanError(
                f"Lean dev check failed for {tag!r}:\n"
                f"stdout:\n{checked.stdout}\n"
                f"stderr:\n{checked.stderr}"
            )
        results.append(LeanCheckResult(tag=tag, lean_file=lean_file))
    return results
