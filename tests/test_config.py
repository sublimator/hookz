from pathlib import Path

import pytest

from hookz.config import ConfigError
from hookz.config import load_config


def test_xahaud_env_injects_path_without_toml(tmp_path, monkeypatch):
    xahaud = tmp_path / "xahaud"
    (xahaud / "hook").mkdir(parents=True)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOOKZ_XAHAUD", str(xahaud))

    config = load_config()

    assert config.xahaud_root == xahaud
    assert config.hook_headers == xahaud / "hook"
    assert config.sources["paths.xahaud"] == "env HOOKZ_XAHAUD"


def test_xahaud_root_env_alias_injects_path_without_toml(tmp_path, monkeypatch):
    xahaud = tmp_path / "xahaud"
    (xahaud / "hook").mkdir(parents=True)

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HOOKZ_XAHAUD", raising=False)
    monkeypatch.setenv("HOOKZ_XAHAUD_ROOT", str(xahaud))

    config = load_config()

    assert config.xahaud_root == xahaud
    assert config.hook_headers == xahaud / "hook"
    assert config.sources["paths.xahaud"] == "env HOOKZ_XAHAUD_ROOT"


def test_hook_entries_accept_string_and_object_forms(tmp_path):
    hookz_toml = tmp_path / "hookz.toml"
    hookz_toml.write_text(
        """
[hooks]
plain = "plain.c"
inline = { source = "inline.c", lean = "inline.lean" }

[hooks.table]
source = "table.c"
lean = "contracts/table.lean"
""",
        encoding="utf-8",
    )

    config = load_config(toml_path=hookz_toml)

    assert config.hooks == {
        "plain": tmp_path / "plain.c",
        "inline": tmp_path / "inline.c",
        "table": tmp_path / "table.c",
    }
    assert config.hook_entries is not None
    assert config.hook_entries["plain"].lean is None
    assert config.hook_entries["inline"].lean == tmp_path / "inline.lean"
    assert config.hook_entries["table"].lean == tmp_path / "contracts" / "table.lean"


def test_hook_entry_local_override_can_add_lean_without_repeating_source(tmp_path):
    hookz_toml = tmp_path / "hookz.toml"
    hookz_toml.write_text(
        """
[hooks]
plain = "plain.c"

[hooks.table]
source = "table.c"
""",
        encoding="utf-8",
    )
    (tmp_path / ".hookz.local.toml").write_text(
        """
[hooks.plain]
lean = "plain.lean"

[hooks.table]
lean = "contracts/table.lean"
""",
        encoding="utf-8",
    )

    config = load_config(toml_path=hookz_toml)

    assert config.hook_entries is not None
    assert config.hook_entries["plain"].source == tmp_path / "plain.c"
    assert config.hook_entries["plain"].lean == tmp_path / "plain.lean"
    assert config.hook_entries["table"].source == tmp_path / "table.c"
    assert config.hook_entries["table"].lean == tmp_path / "contracts" / "table.lean"


def test_hook_entry_rejects_unknown_keys(tmp_path):
    hookz_toml = tmp_path / "hookz.toml"
    hookz_toml.write_text(
        """
[hooks.bad]
source = "bad.c"
status = "todo"
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="unknown keys: status"):
        load_config(toml_path=hookz_toml)


def test_hook_entry_rejects_empty_lean_path(tmp_path):
    hookz_toml = tmp_path / "hookz.toml"
    hookz_toml.write_text(
        """
[hooks.bad]
source = "bad.c"
lean = ""
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="hooks.bad.lean"):
        load_config(toml_path=hookz_toml)
