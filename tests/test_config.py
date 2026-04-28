from pathlib import Path

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
    monkeypatch.setenv("HOOKZ_XAHAUD_ROOT", str(xahaud))

    config = load_config()

    assert config.xahaud_root == xahaud
    assert config.hook_headers == xahaud / "hook"
    assert config.sources["paths.xahaud"] == "env HOOKZ_XAHAUD_ROOT"
