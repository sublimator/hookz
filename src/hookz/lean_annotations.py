"""Lean4 contract bindings for configured hooks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hookz.config import load_config


@dataclass(frozen=True)
class Lean4HookBinding:
    hook: str
    source: Path
    lean: Path


def load_lean4_bindings(toml_path: Path) -> dict[str, Lean4HookBinding]:
    """Load hook entries that have a configured Lean root file."""
    config = load_config(toml_path=toml_path)
    if not config.hook_entries:
        return {}
    return {
        hook: Lean4HookBinding(hook=hook, source=entry.source, lean=entry.lean)
        for hook, entry in config.hook_entries.items()
        if entry.lean is not None
    }
