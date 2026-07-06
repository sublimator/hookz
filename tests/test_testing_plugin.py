from click.testing import CliRunner

from hookz.cli.main import cli
from hookz.testing import plugin


def test_dev_lean_is_enabled_by_default(monkeypatch):
    monkeypatch.delenv("HOOKZ_NO_LEAN", raising=False)
    monkeypatch.delenv("HOOKZ_LEAN", raising=False)
    monkeypatch.setattr(plugin, "_hookz_no_lean", False)

    assert plugin._dev_lean_enabled()


def test_dev_lean_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setenv("HOOKZ_LEAN", "0")
    monkeypatch.setattr(plugin, "_hookz_no_lean", False)

    assert not plugin._dev_lean_enabled()


def test_hookz_test_no_lean_passes_pytest_plugin_option(monkeypatch):
    captured = {}

    def fake_pytest_main(args):
        captured["args"] = args
        return 0

    monkeypatch.setattr("pytest.main", fake_pytest_main)

    result = CliRunner().invoke(cli, ["test", "--no-lean", "-q"])

    assert result.exit_code == 0
    assert captured["args"] == ["--hookz-no-lean", "-q"]
