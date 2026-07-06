"""Lean4 contract annotations for configured hooks."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Lean4HookAnnotation:
    hook: str
    adapter: str
    model: str | None
    status: str
    note: str | None = None


def load_lean4_annotations(toml_path: Path) -> dict[str, Lean4HookAnnotation]:
    """Load `[lean4.<hook>]` annotations from a hookz TOML file."""
    with open(toml_path, "rb") as f:
        data = tomllib.load(f)

    raw_annotations = data.get("lean4", {})
    annotations: dict[str, Lean4HookAnnotation] = {}
    for hook, raw in raw_annotations.items():
        if not isinstance(raw, dict):
            continue
        annotations[hook] = Lean4HookAnnotation(
            hook=hook,
            adapter=str(raw.get("adapter", hook)),
            model=raw.get("model"),
            status=str(raw.get("status", "todo")),
            note=raw.get("note"),
        )
    return annotations
