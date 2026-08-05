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
from test_wasm import _nested_blocks_wasm


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
        """catch_exceptions=False on purpose.

        With the default, CliRunner swallows an escaping exception, sets
        exit_code 1 and puts nothing in `.output` — so `assert "Traceback" not
        in out.output` passes for exactly the failure it claims to exclude.
        The first version of these tests asserted that and could not fail;
        `--coverage` was tracebacking the whole time they were green.
        """
        from click.testing import CliRunner
        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args, catch_exceptions=False)

    # Every path that compiles. --coverage ran zero times in the whole suite
    # before this, which is how its missing handler survived a review that was
    # looking straight at it.
    COMPILING = [
        pytest.param([], id="default"),
        pytest.param(["--coverage"], id="coverage"),
    ]

    @pytest.mark.parametrize("extra", COMPILING)
    def test_a_compile_failure_is_a_message_not_an_exception(
        self, tmp_path, extra
    ):
        """RuntimeError is what the compilers raise when clang fails — the
        most ordinary way for this command to fail at all."""
        bad = tmp_path / "bad.c"
        bad.write_text("this is not valid C;\n")
        out = tmp_path / "bad.wasm"

        r = self._run(["build", str(bad), "-o", str(out), *extra])

        assert r.exception is None or isinstance(r.exception, SystemExit)
        assert r.exit_code == 1
        assert "FAILED" in r.output
        assert not out.exists()

    @pytest.mark.parametrize("extra", COMPILING)
    def test_a_compile_failure_still_flags_a_stale_artifact(
        self, tmp_path, extra
    ):
        """Skipping _build_fail loses this note, so the previous build sits at
        the output path looking current."""
        bad = tmp_path / "bad.c"
        bad.write_text("this is not valid C;\n")
        out = tmp_path / "bad.wasm"
        out.write_bytes(b"\x00asm\x01\x00\x00\x00")

        r = self._run(["build", str(bad), "-o", str(out), *extra])

        assert "stale" in r.output
        assert out.read_bytes() == b"\x00asm\x01\x00\x00\x00"

    def test_wce_reports_the_same_compile_failure_the_same_way(self, tmp_path):
        bad = tmp_path / "bad.c"
        bad.write_text("this is not valid C;\n")

        r = self._run(["wce", str(bad)])

        assert r.exception is None or isinstance(r.exception, SystemExit)
        assert r.exit_code == 1

    @pytest.mark.parametrize("extra", COMPILING)
    def test_every_build_path_names_the_rules_it_judged_under(
        self, tmp_path, extra
    ):
        """How --depth32 turned a rejection into PASSED with nothing in the
        transcript to notice: a verdict was printed and never its basis."""
        r = self._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"), *extra]
        )

        assert r.exit_code == 0, r.output
        assert "rules: 0x01 (nesting limit 16)" in r.output

    def test_guard_check_names_its_rules_on_both_verdicts(self, tmp_path):
        """A depth rejection is exactly when which limit applied is the
        question, so the failing path must say it too."""
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


class TestTheRulesFollowTheNetwork:
    """The constant was `GUARD_RULE_FIX_20250131` — what mainnet happens to
    run. Any test asserting today's answer is vacuous, because today's answer
    IS the constant: `0x01 == 0x01` passes whether or not anything derives.

    So these move the manifest and assert the verdict moves with it. That is
    the only thing that distinguishes deriving from guessing, and the first
    version of these tests — an `inspect.getsource` grep and a comparison
    against the live manifest — was green under `def _rules(): return
    GUARD_RULE_FIX_20250131`.
    """

    @staticmethod
    def _with_depth32(monkeypatch):
        """Pretend mainnet voted fixGuardDepth32 in."""
        import hookz.amendments as amd

        real = amd.enabled_on
        monkeypatch.setattr(
            amd, "enabled_on",
            lambda *a, **k: set(real(*a, **k)) | {"fixGuardDepth32"})

    @pytest.mark.parametrize("extra", TestBuildAndWceAgree.COMPILING)
    def test_a_build_verdict_moves_when_the_network_moves(
        self, tmp_path, monkeypatch, extra
    ):
        self._with_depth32(monkeypatch)

        r = TestBuildAndWceAgree._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"), *extra]
        )

        assert r.exit_code == 0, r.output
        assert "rules: 0x03 (nesting limit 32)" in r.output

    def test_guard_check_moves_too(self, tmp_path, monkeypatch):
        self._with_depth32(monkeypatch)
        art = tmp_path / "h.wasm"
        art.write_bytes(_nested_blocks_wasm(2))

        r = TestBuildAndWceAgree._run(["guard-check", str(art)])

        assert "rules: 0x03 (nesting limit 32)" in r.output

    def test_a_hook_too_deep_today_would_pass_under_the_new_rules(
        self, tmp_path, monkeypatch
    ):
        """The behaviour behind the number, not just the printed line — and
        the reason removing --depth32 lost nothing: when the vote lands this
        happens on its own."""
        art = tmp_path / "deep.wasm"
        art.write_bytes(_nested_blocks_wasm(24))

        before = TestBuildAndWceAgree._run(["guard-check", str(art)])
        assert before.exit_code == 1
        assert "Maximum allowable depth" in before.output

        self._with_depth32(monkeypatch)
        after = TestBuildAndWceAgree._run(["guard-check", str(art)])
        assert after.exit_code == 0, after.output
        assert "PASSED" in after.output

    def test_the_printed_limit_is_the_one_that_was_applied(self, monkeypatch):
        """`nesting limit 16` hardcoded in the message would satisfy every
        assertion above that runs on today's manifest."""
        from hookz.cli.main import _nesting_limit, _rules

        assert _nesting_limit(_rules()) == 16
        self._with_depth32(monkeypatch)
        assert _nesting_limit(_rules()) == 32
