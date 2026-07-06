"""Lean4 hook binding coverage."""

import tomllib
from pathlib import Path

from hookz.config import load_config
from hookz.lean_annotations import load_lean4_bindings


HOOKZ_TOML = Path(__file__).parent / "e2e" / "hookz.toml"

EXPECTED_LEAN_HOOKS = {
    "accept_incoming_xah",
    "balance_gate",
    "mint",
    "multi_invoke_emit",
    "reject_incoming_xah",
    "reward",
    "state_counter",
    "state_toggle",
    "treasury",
}


def test_hookz_toml_has_no_separate_lean4_todo_schema():
    with open(HOOKZ_TOML, "rb") as f:
        data = tomllib.load(f)

    assert "lean4" not in data
    for raw_entry in data["hooks"].values():
        if isinstance(raw_entry, dict):
            assert set(raw_entry) <= {"source", "lean"}


def test_lean4_bindings_are_discovered_from_hook_entries():
    config = load_config(toml_path=HOOKZ_TOML)
    assert config.hook_entries is not None

    bindings = load_lean4_bindings(HOOKZ_TOML)

    assert set(bindings) == {
        hook
        for hook, entry in config.hook_entries.items()
        if entry.lean is not None
    }
    assert set(bindings) == EXPECTED_LEAN_HOOKS


def test_lean4_binding_paths_exist_and_preserve_source_map_compatibility():
    config = load_config(toml_path=HOOKZ_TOML)
    bindings = load_lean4_bindings(HOOKZ_TOML)

    assert config.hooks is not None
    for hook, binding in bindings.items():
        assert binding.source.exists()
        assert binding.lean.exists()
        assert binding.lean.suffix == ".lean"
        assert config.hooks[hook] == binding.source
    assert (
        bindings["balance_gate"].lean
        == HOOKZ_TOML.parent / "hooks" / "misc" / "balance_gate.lean"
    )
