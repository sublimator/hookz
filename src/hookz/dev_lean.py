"""Dispatch development hook checkpoints to Lean checks."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from hookz.config import load_config
from hookz.xfl import xfl_to_float


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class LeanCheckResult:
    tag: str
    lean_file: Path


@dataclass(frozen=True)
class DevCheckContext:
    source_path: Path | None = None
    hook: str | None = None
    lean_file: Path | None = None
    lean_module: str | None = None


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


def _optional_i64(captures: dict[str, dict], name: str) -> int | None:
    event = captures.get(name)
    if event is None:
        return None
    if event.get("kind") != "i64":
        raise DevLeanError(f"capture {name!r} must be an i64")
    value = event.get("value")
    if not isinstance(value, int):
        raise DevLeanError(f"capture {name!r} must be an integer")
    return value


def _bool_literal(value: bool) -> str:
    return "true" if value else "false"


def _verdict_literal(accepted: bool) -> str:
    return ".accept" if accepted else ".reject"


def _xfl_drops_literal(value: int) -> int:
    return int(xfl_to_float(value))


def _lean_module_from_file(lean_file: Path) -> str | None:
    try:
        rel = lean_file.resolve().relative_to((PROJECT_ROOT / "lean").resolve())
    except ValueError:
        return None
    return ".".join(rel.with_suffix("").parts)


def _context_for_source(source_path: Path | None) -> DevCheckContext:
    if source_path is None:
        return DevCheckContext()

    source_path = source_path.resolve()
    try:
        config = load_config(source_file=source_path)
    except Exception:
        return DevCheckContext(source_path=source_path)

    for hook, entry in (config.hook_entries or {}).items():
        if entry.source.resolve() != source_path:
            continue
        lean_file = entry.lean.resolve() if entry.lean is not None else None
        return DevCheckContext(
            source_path=source_path,
            hook=hook,
            lean_file=lean_file,
            lean_module=_lean_module_from_file(lean_file) if lean_file else None,
        )
    return DevCheckContext(source_path=source_path)


def _resolve_tag(tag: str, source_path: Path | None) -> tuple[str, DevCheckContext]:
    context = _context_for_source(source_path)
    if "." not in tag and context.hook:
        return f"{context.hook}.{tag}", context
    return tag, context


def _module(context: DevCheckContext, fallback: str) -> str:
    return context.lean_module or fallback


def _state_counter_after_increment(
    captures: dict[str, dict],
    context: DevCheckContext,
) -> str:
    before = _required_u64(captures, "before_count")
    after = _required_u64(captures, "count")
    module = _module(context, "Hookz.Contracts.StateCounter")
    return f"""import {module}

open Hookz.Contracts

-- generated from hookz dev checkpoint: state_counter.after_increment
example :
    {module}.expected {{
      txKind := .payment,
      owner := false,
      counterState := some {before},
      counterParam := none
    }} = {{ verdict := .accept, counterState := some {after} }} := by
  native_decide
"""


def _balance_gate_after_decision(
    captures: dict[str, dict],
    context: DevCheckContext,
) -> str:
    outgoing = _required_u64(captures, "outgoing") != 0
    accepted = _required_u64(captures, "verdict_accept") != 0
    sender_balance_xfl = _optional_i64(captures, "sender_balance_xfl")
    min_balance_xfl = _optional_i64(captures, "min_balance_xfl")
    sender_balance = (
        "none"
        if sender_balance_xfl is None
        else f"some {_xfl_drops_literal(sender_balance_xfl)}"
    )
    min_balance = (
        10000000
        if min_balance_xfl is None
        else _xfl_drops_literal(min_balance_xfl)
    )
    module = _module(context, "Hookz.Contracts.BalanceGate")
    return f"""import {module}

open Hookz.Contracts

-- generated from hookz dev checkpoint: balance_gate.after_decision
example :
    {module}.expected {{
      outgoing := {_bool_literal(outgoing)},
      senderBalanceDrops := {sender_balance},
      minBalanceDrops := {min_balance}
    }} = {_verdict_literal(accepted)} := by
  native_decide
"""


_ADAPTERS: dict[str, Callable[[dict[str, dict], DevCheckContext], str]] = {
    "balance_gate.after_decision": _balance_gate_after_decision,
    "state_counter.after_increment": _state_counter_after_increment,
}


def render_dev_lean_checks(
    events: list[dict],
    source_path: Path | None = None,
) -> list[tuple[str, str]]:
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
            resolved_tag, context = _resolve_tag(tag, source_path)
            adapter = _ADAPTERS.get(resolved_tag)
            if adapter is None:
                raise DevLeanError(f"no Lean dev adapter registered for {resolved_tag!r}")
            rendered.append((resolved_tag, adapter(_capture_map(pending), context)))
            pending = []
        else:
            pending.append(event)
    return rendered


def dispatch_dev_lean_checks(
    events: list[dict],
    out_dir: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    source_path: Path | None = None,
) -> list[LeanCheckResult]:
    """Generate and check Lean files for recorded development hook events."""
    lake = _lake_binary()
    if lake is None:
        raise DevLeanError("lake not found; install Lean or set LAKE")

    if out_dir is None:
        out_dir = Path(os.environ.get("HOOKZ_LEAN_DEV_DIR", "/tmp/hookz-lean-dev-checks"))
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[LeanCheckResult] = []
    for index, (tag, lean_source) in enumerate(
        render_dev_lean_checks(events, source_path=source_path), 1
    ):
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
