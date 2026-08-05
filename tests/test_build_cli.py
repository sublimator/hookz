"""Tests for the `hookz build` pipeline's output-writing contract.

The pipeline is compile → optimize → clean → guard-check → write. Only the
last step may touch the output path: a binary that has been compiled but not
cleaned still carries custom sections, which xahaud rejects outright. Leaving
one at the output path on failure hands the user something that looks like a
build artifact and is not deployable.
"""

from pathlib import Path

import pytest

from hookz.cli.main import _build_normal
from hookz.config import load_config
from hookz.wasm.decode import decode_module
from hookz.wasm.guard import GuardError


SOURCE = Path("tests/e2e/hooks/misc/balance_gate.c")


@pytest.fixture(scope="module")
def config():
    return load_config(source_file=SOURCE)


class TestBuildOutputWriting:
    def test_writes_cleaned_output_on_success(self, tmp_path, config):
        out = tmp_path / "hook.wasm"
        with pytest.raises(SystemExit) as exc:
            _build_normal(SOURCE, out, config)
        assert exc.value.code == 0
        assert out.exists()
        # what landed is the cleaned binary, not the raw compile
        assert len(decode_module(out.read_bytes()).custom_sections) == 0

    def test_no_output_written_when_guard_check_fails(
        self, tmp_path, config, monkeypatch
    ):
        """The regression: a failed guard check must leave nothing behind."""
        import hookz.wasm.guard as guard_mod

        def _reject(*args, **kwargs):
            raise GuardError("Maximum allowable depth of blocks reached (16 levels).")

        monkeypatch.setattr(guard_mod, "validate_guards", _reject)

        out = tmp_path / "hook.wasm"
        with pytest.raises(SystemExit) as exc:
            _build_normal(SOURCE, out, config)
        assert exc.value.code == 1
        assert not out.exists(), "failed build left an unvalidated artifact behind"

    def test_no_output_written_when_clean_fails(self, tmp_path, config, monkeypatch):
        import hookz.wasm.clean as clean_mod

        def _explode(*args, **kwargs):
            raise clean_mod.CleanError("boom")

        monkeypatch.setattr(clean_mod, "clean_hook", _explode)

        out = tmp_path / "hook.wasm"
        with pytest.raises(SystemExit) as exc:
            _build_normal(SOURCE, out, config)
        assert exc.value.code == 1
        assert not out.exists()

    def test_stale_artifact_is_called_out(self, tmp_path, config, monkeypatch, capsys):
        """A prior build's output survives a failure — say it is now stale.

        Nothing is overwritten, so the danger is the opposite of the original
        bug: a good-looking file at the expected path that no longer matches
        the source just compiled.
        """
        import hookz.wasm.guard as guard_mod

        def _reject(*args, **kwargs):
            raise GuardError("nope")

        monkeypatch.setattr(guard_mod, "validate_guards", _reject)

        out = tmp_path / "hook.wasm"
        out.write_bytes(b"\x00asm\x01\x00\x00\x00previous build")

        with pytest.raises(SystemExit):
            _build_normal(SOURCE, out, config)

        assert "stale" in capsys.readouterr().out
        # untouched, not silently deleted — the user decides what to do with it
        assert out.read_bytes().endswith(b"previous build")


class TestCompileTempFiles:
    """compile_hook(output=None) must not litter the temp dir.

    Every `hookz build` and every `hookz wce` fallback takes this path, so a
    leak here accumulates one stray .wasm per invocation, indefinitely.
    """

    def test_no_temp_left_behind(self, config):
        import tempfile
        from hookz.compiler import compile_hook

        tmpdir = Path(tempfile.gettempdir())
        before = set(tmpdir.glob("tmp*.wasm"))
        wasm = compile_hook(SOURCE, None, config, debug=False, optimize=True)
        after = set(tmpdir.glob("tmp*.wasm"))

        assert wasm[:4] == b"\x00asm"
        assert after - before == set()

    def test_caller_supplied_output_is_kept(self, tmp_path, config):
        """Cleanup must apply only to the temp we created."""
        from hookz.compiler import compile_hook

        out = tmp_path / "explicit.wasm"
        compile_hook(SOURCE, out, config, debug=False, optimize=True)
        assert out.exists()

    def test_no_temp_left_behind_on_compile_failure(self, tmp_path, config):
        import tempfile
        from hookz.compiler import compile_hook

        bad = tmp_path / "bad.c"
        bad.write_text("this is not valid C;\n")

        tmpdir = Path(tempfile.gettempdir())
        before = set(tmpdir.glob("tmp*.wasm"))
        with pytest.raises(RuntimeError, match="Compilation failed"):
            compile_hook(bad, None, config, debug=False, optimize=True)
        assert set(tmpdir.glob("tmp*.wasm")) - before == set()


class TestPipelineSelection:
    """`--pipeline` is a flag value, so a name it will not take is bad usage.

    Untested until a reviewer found `--pipeline buildbox` exiting 1 through
    _build_fail — which then printed the stale-artifact note below, about a
    build that had not run. Both symptoms come from routing a rejected flag
    value into the failure path for a build that started and died.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner
        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args)

    def test_a_refused_name_exits_two_and_points_at_both_real_options(
        self, tmp_path
    ):
        out = self._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"),
             "--pipeline", "buildbox"]
        )
        assert out.exit_code == 2, out.output
        # Not asserted on "buildbox": that is in the input, so it also appears
        # in the generic "unknown build pipeline 'buildbox'" message and the
        # pointer could rot away with this still green.
        assert "--buildbox" in out.output
        assert "--pipeline local-structural" in out.output

    def test_a_refused_name_does_not_call_a_good_artifact_stale(self, tmp_path):
        """The reported bug. Nothing was compiled, so nothing became stale —
        and the file it maligned was the last good build."""
        artifact = tmp_path / "h.wasm"
        artifact.write_bytes(b"\x00asm\x01\x00\x00\x00")

        out = self._run(
            ["build", str(SOURCE), "-o", str(artifact),
             "--pipeline", "buildbox"]
        )

        assert "stale" not in out.output
        assert artifact.read_bytes() == b"\x00asm\x01\x00\x00\x00"

    def test_an_unknown_name_is_usage_not_a_failed_build(self, tmp_path):
        out = self._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"),
             "--pipeline", "no-such-pipeline"]
        )
        assert out.exit_code == 2, out.output
        assert "local-structural" in out.output
        assert "stale" not in out.output

    def test_build_and_wce_agree_on_a_refused_name(self, tmp_path):
        """They resolve the same flag through the same function; disagreeing
        on the exit code makes one of them wrong for a scripted caller."""
        build = self._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"),
             "--pipeline", "buildbox"]
        )
        wce = self._run(["wce", str(SOURCE), "--pipeline", "buildbox"])
        assert build.exit_code == wce.exit_code == 2

    def test_a_real_pipeline_still_builds(self, tmp_path):
        out = self._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"),
             "--pipeline", "local-structural"]
        )
        assert out.exit_code == 0, out.output
        assert (tmp_path / "h.wasm").exists()


class TestPipelinesListing:
    """`hookz pipelines` had no test at all, so deleting its rejection block
    was a green mutation."""

    @staticmethod
    def _run():
        from click.testing import CliRunner
        from hookz.cli.main import cli

        return CliRunner().invoke(cli, ["pipelines"])

    def test_lists_every_pipeline_the_flag_accepts(self):
        from hookz.wasm.pipeline import BUILD_PIPELINES

        out = self._run()
        assert out.exit_code == 0, out.output
        for name in BUILD_PIPELINES:
            assert name in out.output

    def test_names_the_refused_spelling_and_where_to_go(self):
        """Someone who learned the old name should be told it is gone, not
        left to read "unknown pipeline" and wonder if the service went too."""
        out = self._run()
        assert "buildbox" in out.output
        assert "--buildbox" in out.output
        assert "local-structural" in out.output

    def test_does_not_offer_a_refused_name_as_a_choice(self):
        """It used to print `legacy alias: buildbox → local-structural`."""
        out = self._run()
        assert "alias" not in out.output.lower()


class TestBuildAndWceAgree:
    """`wce` was rewritten and hardened; `build` was not, and the gap kept
    producing defects — a traceback where wce printed a message, a hardcoded
    rules constant where wce derived one, and a silent verdict where wce named
    its rules. These pin the symmetry rather than the individual fixes.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner
        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args)

    def test_a_compile_failure_is_a_message_not_a_traceback(self, tmp_path):
        """RuntimeError is what compile_hook raises when clang fails — the
        most ordinary way for this command to fail at all."""
        bad = tmp_path / "bad.c"
        bad.write_text("this is not valid C;\n")

        out = self._run(
            ["build", str(bad), "-o", str(tmp_path / "bad.wasm")]
        )

        assert out.exit_code == 1
        assert "Compile FAILED" in out.output
        assert "Traceback" not in out.output
        assert not (tmp_path / "bad.wasm").exists()

    def test_wce_reports_the_same_compile_failure_the_same_way(self, tmp_path):
        bad = tmp_path / "bad.c"
        bad.write_text("this is not valid C;\n")

        out = self._run(["wce", str(bad)])

        assert out.exit_code == 1
        assert "Traceback" not in out.output

    def test_the_build_verdict_names_the_rules_it_judged_under(self, tmp_path):
        """How --depth32 turned a rejection into PASSED with nothing in the
        transcript to notice: build printed a verdict and never its rules."""
        out = self._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm")]
        )

        assert out.exit_code == 0, out.output
        assert "rules: 0x" in out.output
        assert "nesting limit" in out.output

    def test_guard_check_names_its_rules_on_both_verdicts(self, tmp_path):
        """A depth rejection is exactly when which limit applied is the
        question, so the failing path must say it too."""
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from test_wasm import _nested_blocks_wasm

        deep = tmp_path / "deep.wasm"
        deep.write_bytes(_nested_blocks_wasm(24))
        shallow = tmp_path / "ok.wasm"
        shallow.write_bytes(_nested_blocks_wasm(2))

        failed = self._run(["guard-check", str(deep)])
        assert failed.exit_code == 1
        assert "FAILED" in failed.output
        assert "nesting limit 16" in failed.output

        passed = self._run(["guard-check", str(shallow)])
        assert "nesting limit 16" in passed.output

    def test_no_build_path_hardcodes_the_rules_version(self):
        """All three used `rules_version = GUARD_RULE_FIX_20250131`, which is
        what mainnet happens to run — right by coincidence, and unable to
        notice the network moving. The constant must not reappear."""
        import inspect

        from hookz.cli import main as cli_main

        for fn in (cli_main._build_normal, cli_main._build_buildbox,
                   cli_main._build_coverage):
            src = inspect.getsource(fn)
            assert "GUARD_RULE_FIX_20250131" not in src, fn.__name__
            assert "_rules()" in src, fn.__name__

    def test_every_build_path_derives_the_same_rules_as_wce(self):
        from hookz.amendments import guard_rules_version
        from hookz.cli.main import _rules

        assert _rules() == guard_rules_version()
