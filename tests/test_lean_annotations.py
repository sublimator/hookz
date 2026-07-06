"""Lean4 hook annotation coverage."""

import tomllib
from pathlib import Path

from hookz.dev_directives import extract_hookz_lean4_annotations
from hookz.lean_annotations import load_lean4_annotations


HOOKZ_TOML = Path(__file__).parent / "e2e" / "hookz.toml"
E2E_ROOT = HOOKZ_TOML.parent


def test_every_configured_hook_has_lean4_annotation():
    with open(HOOKZ_TOML, "rb") as f:
        data = tomllib.load(f)

    hooks = set(data["hooks"])
    annotations = load_lean4_annotations(HOOKZ_TOML)

    assert set(annotations) == hooks


def test_modeled_lean4_annotations_have_models():
    annotations = load_lean4_annotations(HOOKZ_TOML)

    modeled = [annotation for annotation in annotations.values() if annotation.status == "modeled"]

    assert modeled
    for annotation in modeled:
        assert annotation.model
        assert annotation.model.startswith("Hookz.Contracts.")


def test_parent_owned_modeled_hooks_have_matching_source_metadata():
    with open(HOOKZ_TOML, "rb") as f:
        data = tomllib.load(f)

    annotations = load_lean4_annotations(HOOKZ_TOML)
    for hook, source in data["hooks"].items():
        if source.startswith("hooks/XahauHooks101/"):
            continue
        annotation = annotations[hook]
        if annotation.status != "modeled":
            continue

        source_annotations = extract_hookz_lean4_annotations(E2E_ROOT / source)
        assert source_annotations, f"{hook} has no source lean4 metadata"
        assert any(
            item.adapter == annotation.adapter and item.model == annotation.model
            for item in source_annotations
        ), f"{hook} source metadata does not match hookz.toml"
