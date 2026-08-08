"""Tests for the `hookz build` pipeline's output-writing contract.

The pipeline is compile → optimize → clean → guard-check → write. Only the
last step may touch the output path: a binary that has been compiled but not
cleaned still carries custom sections, which xahaud rejects outright. Leaving
one at the output path on failure hands the user something that looks like a
build artifact and is not deployable.
"""

from contextlib import contextmanager
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


@pytest.fixture(scope="module")
def hook_artifact(tmp_path_factory, config):
    """A real compiled hook on disk, for tests that need an artifact path.

    Compiled from the module's own tracked SOURCE. The tests that use this
    previously read tests/e2e/hooks/genesis/govern.wasm — an e2e build
    artifact `.gitignore` (`*.wasm`) keeps out of the repo, so it existed
    only where an e2e run had happened to leave it, and the tests failed at
    the artifact everywhere else, including CI.
    """
    from hookz.compiler import compile_hook

    out = tmp_path_factory.mktemp("artifact") / "balance_gate.wasm"
    compile_hook(SOURCE, out, config, debug=False, optimize=True)
    return out


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


@contextmanager
def suppressed_unlink():
    """Disable `Path.unlink` for the duration, recording what it spared.

    `compile_hook`'s cleanup is a single `out_path.unlink(missing_ok=True)`
    in a `finally` (hookz:src/hookz/compiler.py:151-156). Suppressing exactly
    that call is how a test can make the function leak on purpose, without
    reaching inside it for the temp's name.
    """
    spared: list[Path] = []
    real = Path.unlink

    def fake(self, *args, **kwargs):
        spared.append(self)

    Path.unlink = fake
    try:
        yield spared
    finally:
        Path.unlink = real


@pytest.fixture
def private_tmpdir(tmp_path, monkeypatch):
    """Redirect `compile_hook`'s unnamed temp into a directory only we use.

    `compile_hook(output=None)` calls `NamedTemporaryFile` with no `dir=`, so
    it lands wherever `tempfile.gettempdir()` points — shared with every other
    process on the machine. A leak test that globs that directory cannot tell
    "we left a file behind" from "somebody else created one", and says the
    former either way.

    > Running a second test suite on the same machine failed
    > `test_no_temp_left_behind_on_compile_failure` with a stray
    > `tmpqahhnpc3.wasm` that this process never opened. Nothing had leaked.

    Setting `tempfile.tempdir` rather than `TMPDIR` is deliberate:
    `gettempdir()` reads the environment once and caches the answer, so by the
    time a test runs the variable is no longer consulted.

    That also bounds what these tests cover. The redirection reaches Python's
    `tempfile`, which is how `compile_hook` opens its output; the subprocesses
    it spawns still inherit the real `TMPDIR`, so a temp file leaked by clang,
    wasm-ld or wasm-opt is out of scope here — as it was before, since the old
    `tmp*.wasm` glob would not have named one either.
    """
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return tmp_path


class TestCompileTempFiles:
    """compile_hook(output=None) must not litter the temp dir.

    Every `hookz build` and every `hookz wce` fallback takes this path, so a
    leak here accumulates one stray .wasm per invocation, indefinitely.
    """

    def test_no_temp_left_behind(self, private_tmpdir, config):
        from hookz.compiler import compile_hook

        wasm = compile_hook(SOURCE, None, config, debug=False, optimize=True)

        assert wasm[:4] == b"\x00asm"
        assert list(private_tmpdir.rglob("*.wasm")) == []

    def test_caller_supplied_output_is_kept(self, tmp_path, config):
        """Cleanup must apply only to the temp we created."""
        from hookz.compiler import compile_hook

        out = tmp_path / "explicit.wasm"
        compile_hook(SOURCE, out, config, debug=False, optimize=True)
        assert out.exists()

    def test_no_temp_left_behind_on_compile_failure(self, private_tmpdir,
                                                    config):
        from hookz.compiler import compile_hook

        bad = private_tmpdir / "bad.c"
        bad.write_text("this is not valid C;\n")

        with pytest.raises(RuntimeError, match="Compilation failed"):
            compile_hook(bad, None, config, debug=False, optimize=True)
        assert list(private_tmpdir.rglob("*.wasm")) == []

    def test_the_leak_tests_would_notice_a_leak(self, private_tmpdir, config):
        """The control: a temp left behind has to fail the assertions above.

        Both tests glob a directory this process owns, which is what makes
        them meaningful — but an empty glob also passes when the redirection
        silently missed and the file went to the real temp dir. So make
        `compile_hook` leak, and confirm the glob names it.

        Leaking it through `compile_hook` rather than by opening a
        `NamedTemporaryFile` here is the point. This asserts on the path the
        tested code actually takes, so if that code moves to `mkstemp(dir=…)`
        or a `TemporaryDirectory`, the leak tests go inert *and this fails*
        rather than passing on an API nothing uses any more.
        """
        from hookz.compiler import compile_hook

        # the cleanup under test: it unlinks the temp it made when output is
        # None. Take the unlink away and the same call must leave the file.
        with suppressed_unlink() as leaked:
            compile_hook(SOURCE, None, config, debug=False, optimize=True)

        found = list(private_tmpdir.rglob("*.wasm"))
        assert found, "compile_hook did not open its temp through tempfile"
        assert [p.name for p in found] == [p.name for p in leaked]
        assert found[0].parent == private_tmpdir


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

    def test_wce_moves_too(self, tmp_path, monkeypatch):
        """The one verdict command this class had never covered.

        `wce` renders the line through Rich rather than print, so it lives
        outside the plain-text path the other two share, and its only coverage
        was `assert "rules: 0x01 (nesting limit 16)" in output` — today's
        constant, which a hardcoded 16 satisfies. A reviewer planted a
        `%`-format copy in `wce` that printed 0x03 alongside a hardcoded limit
        of 16, and the whole suite stayed green while `build` and `wce`
        disagreed on the same manifest.

        The structural tests in TestTheDisclosureHasOneSource are substring
        blacklists — `"nesting limit {"`, `"  rules:"`, `"rules:[/dim]"` — so
        a copy avoiding all three passes them. This closes it behaviourally
        instead, where the shape of the format string does not matter.
        """
        self._with_depth32(monkeypatch)
        art = tmp_path / "h.wasm"
        art.write_bytes(_nested_blocks_wasm(2))

        r = TestBuildAndWceAgree._run(["wce", str(art)])

        assert "rules: 0x03 (nesting limit 32)" in r.output, r.output

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


class TestTheDisclosureHasOneSource:
    """It has been consolidated twice and split again both times.

    First as a line copied per call site; then as a module helper that
    `guard_check` shadowed with a same-named local closure while `wce` kept a
    third copy with its own markup. Identical rendering by hand is not the
    same as one source, and a reviewer had to run disjoint mutations to show
    the difference.
    """

    # Whole modules, not `vars(module)`. The first version walked module
    # globals and filtered on `hasattr(fn, "__code__")` — which every
    # @cli.command() fails, because click replaces the function with a
    # `Command` instance. So the scan set was 26 helpers and excluded `build`,
    # `wce` and `guard_check`: the two functions that had ever held a copy
    # were the two it could not see. Restoring either offender verbatim left
    # the whole suite green.
    MODULES = ["hookz.cli.main", "hookz.cli.doctor"]

    @staticmethod
    def _statements(module_name, excluding="_rules_line"):
        """Source statements with continuations joined, minus the formatter.

        Per-line matching was evadable by splitting the f-string one token
        earlier — `log("  rules: " f"0x{v:02X} …")` matched nothing. `ast`
        joins them. The formatter's own body is excluded or it reports itself.
        """
        import ast
        import importlib
        import inspect

        src = inspect.getsource(importlib.import_module(module_name))
        tree = ast.parse(src)

        skip = range(0)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == excluding:
                skip = range(node.lineno, (node.end_lineno or node.lineno) + 1)

        return [
            (n.lineno, ast.unparse(n))
            for n in ast.walk(tree)
            if isinstance(n, ast.stmt) and n.lineno not in skip
            and not isinstance(n, (ast.FunctionDef, ast.ClassDef))
        ]

    def test_nothing_in_the_cli_formats_its_own_rules_line(self):
        """Positive rule: the numbers come from _rules_line or not at all."""
        # "nesting limit {" — interpolated, so the --ignore-depth help text
        # ("Waive the block nesting limit …") is prose and not a renderer.
        offenders = [
            f"main.py:{lineno} {stmt.splitlines()[0]}"
            for lineno, stmt in self._statements("hookz.cli.main")
            if "nesting limit {" in stmt and "_rules_line" not in stmt
        ]
        assert not offenders, (
            "hand-formatted rules line(s): " + "; ".join(offenders))

    def test_the_formatter_is_the_only_producer_of_the_label(self):
        """Counted, so a second producer is a failure rather than a shape the
        blacklist happened not to match."""
        producers = [
            stmt for _, stmt in self._statements("hookz.cli.main")
            if "  rules:" in stmt or "rules:[/dim]" in stmt
        ]
        assert producers == [], producers

    class _Rep:
        """Enough of _Report to record what doctor tried to say."""

        def __init__(self):
            self.rows = []

        def section(self, *a):
            pass

        def info(self, label, value):
            self.rows.append((label, value))

        def optional(self, label, detail="", hint=""):
            self.rows.append(("optional", detail))

    @staticmethod
    def _doctor_rows():
        from hookz.cli.doctor import _check_guard_rules

        rep = TestTheDisclosureHasOneSource._Rep()
        _check_guard_rules(rep)
        return rep.rows

    def test_doctor_reports_the_same_numbers_in_its_own_layout(
        self, monkeypatch
    ):
        """doctor renders labelled report rows, not the one-line disclosure —
        a different presentation, legitimately. What must not differ is the
        numbers, so bind those rather than the string.

        Asserted twice, the second time off the constant. On today's manifest
        this reads `0x01 == 0x01`, which a hardcoded literal satisfies just as
        well as a derivation — the same vacuity `TestTheRulesFollowTheNetwork`
        exists to rule out, reintroduced here because one assertion looked
        obviously sufficient.
        """
        from hookz.cli.main import _nesting_limit, _rules

        reported = dict(self._doctor_rows())
        assert reported["rulesVersion"] == f"0x{_rules():02X}"
        assert reported["nesting limit"] == str(_nesting_limit(_rules()))

        TestTheRulesFollowTheNetwork._with_depth32(monkeypatch)
        moved = dict(self._doctor_rows())
        assert moved["rulesVersion"] == "0x03"
        assert moved["nesting limit"] == "32"

    def test_a_corrupt_manifest_is_a_row_not_a_traceback(self, monkeypatch):
        """The regression this class's own change caused.

        `resolve_rules` catches the read failure and returns 0, so the handler
        it was wrapped in became unreachable and `provenance()` — the very next
        line, same file, a route that does raise — took the process out. A
        diagnostic command tracebacking on a broken environment is the worst
        available failure mode: it is the state the command exists to name.
        """
        import hookz.amendments as amd

        def _corrupt(*a, **k):
            raise ValueError("Expecting property name: line 1 column 3")

        monkeypatch.setattr(amd, "manifest", _corrupt)

        with pytest.warns(RuntimeWarning):
            rows = self._doctor_rows()

        assert rows == [("optional", "could not read the manifest: "
                         "Expecting property name: line 1 column 3")], rows

    def test_the_degraded_report_is_not_half_a_report(self, monkeypatch):
        """guard_rules_explained() reads the manifest too, and it is called
        after two rows are already on the page. Rendering nothing until every
        read has succeeded is what keeps a failure from printing a network
        line and a rulesVersion and then giving up mid-section."""
        import hookz.amendments as amd

        monkeypatch.setattr(
            amd, "guard_rules_explained",
            lambda *a, **k: (_ for _ in ()).throw(OSError("gone")))

        rows = self._doctor_rows()

        assert [label for label, _ in rows] == ["optional"], rows

    def test_doctor_degrades_by_the_same_route_every_verdict_uses(
        self, monkeypatch
    ):
        """The whole point of routing through `resolve_rules`, and the only
        consequence of it that is observable at all.

        Both routes return 0x01 today, so no assertion on the number can tell
        them apart. They differ in exactly one place: `resolve_rules` warns
        that its answer is degraded before returning 0, and
        `guard_rules_version` just raises. Reverting doctor to the direct call
        still produces the diagnostic row — the try covers it — but silently.
        """
        import hookz.amendments as amd

        monkeypatch.setattr(
            amd, "manifest",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("bad json")))

        with pytest.warns(RuntimeWarning, match="more permissive than the "
                          "network"):
            self._doctor_rows()

    @pytest.mark.parametrize("module_name", MODULES)
    def test_no_name_shadows_the_helper(self, module_name):
        """`guard_check` defined its own `_say_rules(emit=print)` inside a
        module that already had `_say_rules(rules_version, log)` — a nested
        def, invisible to a scan that never reached the command."""
        import ast
        import importlib
        import inspect

        src = inspect.getsource(importlib.import_module(module_name))
        defs = [
            n.name for n in ast.walk(ast.parse(src))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for helper in ("_say_rules", "_rules_line"):
            assert defs.count(helper) <= 1, f"{helper} defined twice"

    def test_the_dim_variant_says_the_same_numbers(self):
        from rich.markup import render
        from hookz.cli.main import _rules_line

        plain = _rules_line(0x03)
        dim = render(_rules_line(0x03, dim=True)).plain
        assert plain == dim
        assert "0x03" in plain
        assert "nesting limit 32" in plain


class TestCoverageBuildFailuresAreReported:
    """The instrument stage shells out to llvm-dwarfdump, so it fails on
    machines where the compile stage is fine — `hookz doctor` checks for the
    tool precisely because it is often absent. It was the one stage left
    unguarded when the coverage path grew a handler.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner
        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args, catch_exceptions=False)

    @pytest.mark.parametrize(
        "message",
        [
            "llvm-dwarfdump not found. Install LLVM tools:",
            "llvm-dwarfdump failed: exit 1",
            "No DWARF source locations found. Compile with -g.",
        ],
    )
    def test_an_instrument_failure_is_a_verdict_not_a_traceback(
        self, tmp_path, monkeypatch, message
    ):
        def _die(*a, **k):
            raise RuntimeError(message)

        monkeypatch.setattr("hookz.coverage.rewriter.instrument_wasm", _die)
        artifact = tmp_path / "h.wasm"
        artifact.write_bytes(b"\x00asm\x01\x00\x00\x00")

        r = self._run(
            ["build", str(SOURCE), "-o", str(artifact), "--coverage"]
        )

        assert r.exit_code == 1
        assert "Build FAILED" in r.output
        assert message in r.output
        # the artifact it did not replace must not be left looking current
        assert "stale" in r.output
        assert artifact.read_bytes() == b"\x00asm\x01\x00\x00\x00"


class TestTheRulesLineFollowsItsVerdict:
    """It read as a property of the build when it printed first, and put
    build in disagreement with guard-check, which printed it after."""

    @staticmethod
    def _lines(output):
        return [ln.strip() for ln in output.splitlines() if ln.strip()]

    def _assert_rules_after_verdict(self, output):
        lines = self._lines(output)
        verdict = next(i for i, ln in enumerate(lines) if "Guard check" in ln)
        rules = next(i for i, ln in enumerate(lines) if ln.startswith("rules:"))
        assert rules > verdict, output

    @pytest.mark.parametrize("extra", TestBuildAndWceAgree.COMPILING)
    def test_on_a_passing_build(self, tmp_path, extra):
        r = TestBuildAndWceAgree._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"), *extra]
        )
        assert r.exit_code == 0, r.output
        self._assert_rules_after_verdict(r.output)

    @pytest.mark.parametrize("extra", TestBuildAndWceAgree.COMPILING)
    def test_on_a_rejected_build(self, tmp_path, monkeypatch, extra):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda *a, **k: (_ for _ in ()).throw(
                GuardError("Maximum allowable depth of blocks reached (16 levels).")),
        )

        r = TestBuildAndWceAgree._run(
            ["build", str(SOURCE), "-o", str(tmp_path / "h.wasm"), *extra]
        )

        assert r.exit_code == 1
        self._assert_rules_after_verdict(r.output)

    def test_guard_check_agrees_on_both_outcomes(self, tmp_path):
        deep = tmp_path / "deep.wasm"
        deep.write_bytes(_nested_blocks_wasm(24))
        shallow = tmp_path / "ok.wasm"
        shallow.write_bytes(_nested_blocks_wasm(2))

        for art in (deep, shallow):
            r = TestBuildAndWceAgree._run(["guard-check", str(art)])
            self._assert_rules_after_verdict(r.output)


class TestWriteFailuresAreVerdicts:
    """The last unguarded stage, and the worst place to traceback: the build
    succeeded, the guard check passed, the verdict and rules printed — then
    the process died on `-o` naming a directory that does not exist.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner
        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args, catch_exceptions=False)

    @pytest.mark.parametrize("extra", TestBuildAndWceAgree.COMPILING)
    def test_a_missing_output_directory_is_reported(self, tmp_path, extra):
        r = self._run(
            ["build", str(SOURCE),
             "-o", str(tmp_path / "no" / "such" / "dir" / "h.wasm"), *extra]
        )

        assert r.exit_code == 1
        assert "Write FAILED" in r.output
        # the distinction that matters: nothing was wrong with the binary
        assert "passed every check" in r.output

    def test_an_unwritable_path_is_reported(self, tmp_path):
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o500)
        try:
            r = self._run(
                ["build", str(SOURCE), "-o", str(locked / "h.wasm")]
            )
            assert r.exit_code == 1
            assert "Write FAILED" in r.output
        finally:
            locked.chmod(0o700)

    def test_clean_reports_it_too(self, tmp_path):
        art = tmp_path / "in.wasm"
        TestBuildAndWceAgree._run(
            ["build", str(SOURCE), "-o", str(art)]
        )

        r = self._run(
            ["clean", str(art), "-o", str(tmp_path / "no" / "dir" / "o.wasm")]
        )

        assert r.exit_code == 1
        assert "Write FAILED" in r.output

    def test_a_writable_path_still_writes(self, tmp_path):
        out = tmp_path / "h.wasm"
        r = self._run(["build", str(SOURCE), "-o", str(out)])
        assert r.exit_code == 0, r.output
        assert out.read_bytes()[:4] == b"\x00asm"


class TestAMistypedPathIsAUsageErrorNotATraceback:
    """`click.Path` defaults to `dir_okay=True`, so a directory passed
    validation and died one line later on the read.

    Found alongside the write guarding, and worth stating together: `clean`'s
    *write* was guarded while its *read* tracebacked on the same mistyped
    path, one line earlier.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner

        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args, catch_exceptions=False)

    @pytest.mark.parametrize(
        "argv",
        [
            pytest.param(["guard-check", "{d}"], id="guard-check"),
            pytest.param(["clean", "{d}", "-o", "{d}/o.wasm"], id="clean"),
            pytest.param(["build", "{d}", "-o", "{d}/o.wasm"], id="build"),
            pytest.param(["debug-compile", "{d}"], id="debug-compile"),
            pytest.param(["surface", "{d}"], id="surface"),
        ],
    )
    def test_a_directory_is_refused(self, tmp_path, argv):
        r = self._run([a.format(d=tmp_path) for a in argv])

        assert r.exit_code != 0
        assert "directory" in r.output.lower(), r.output
        assert "Traceback" not in r.output


class TestSourceTheBuildboxCannotBeGivenIsAVerdict:
    """The buildbox takes source as text, so both call sites did a bare
    `read_text()` inside a `try` that catches only `BuildboxError`.

    A latin-1 byte in a comment is an ordinary thing to have in a C file, and
    it came out as a UnicodeDecodeError traceback from `build --buildbox` and
    `wce --buildbox` alike. Neither reaches the network, so neither test needs
    it.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner

        from hookz.cli.main import cli

        return CliRunner().invoke(cli, args, catch_exceptions=False)

    @pytest.fixture
    def latin1_hook(self, tmp_path):
        p = tmp_path / "bad.c"
        p.write_bytes(b"// caf\xe9 latin-1\nint hook(uint32_t r){return 0;}\n")
        return p

    def test_build_says_which_byte_and_where(self, tmp_path, latin1_hook):
        r = self._run(["build", str(latin1_hook), "-o",
                       str(tmp_path / "o.wasm"), "--buildbox"])

        assert r.exit_code == 1
        assert "not valid UTF-8" in r.output
        assert "0xe9" in r.output and "offset 6" in r.output
        assert "Traceback" not in r.output

    def test_wce_says_the_same_thing(self, latin1_hook):
        r = self._run(["wce", str(latin1_hook), "--buildbox"])

        assert r.exit_code != 0
        assert "not valid UTF-8" in r.output
        assert "Traceback" not in r.output


class TestTheEnvironmentErrorsAreRenderedNotRaised:
    """`WhitelistError` and `ManifestError` are handled in `main()`, which
    wraps `cli` — and every other CLI test here uses
    `CliRunner().invoke(cli, ...)`, which enters below that wrapper. So both
    handlers, and the two commits that added them, were structurally
    unreachable from the suite: verified by hand once and then unguarded.

    These go through `main()` itself.
    """

    @staticmethod
    def _main(argv, monkeypatch, capsys):
        import sys as _sys

        from hookz.cli.main import main

        monkeypatch.setattr(_sys, "argv", ["hookz", *argv])
        with pytest.raises(SystemExit) as exc:
            main()
        captured = capsys.readouterr()
        return exc.value.code, captured.out + captured.err

    def test_a_corrupt_manifest_is_rendered_as_the_installation_s_problem(
        self, monkeypatch, capsys, hook_artifact
    ):
        import hookz.amendments as amd

        def _boom(*a, **k):
            raise amd.ManifestError("amendments-mainnet.json: bad json")

        monkeypatch.setattr(amd, "manifest", _boom)

        # A real artifact: a stub too small to be a hook fails the size check
        # before anything reads the manifest, so the handler never runs and
        # the test passes for the wrong reason.
        art = hook_artifact

        # resolve_rules catches this one and degrades to 0x00 with a warning
        # before the whitelist read raises it for real. Asserted rather than
        # left as a stray warning: that degradation is the behaviour doctor
        # depends on, and it is why both types subclass ValueError.
        with pytest.warns(RuntimeWarning, match="more permissive"):
            code, out = self._main(
                ["guard-check", str(art)], monkeypatch, capsys)

        assert code == 1
        assert "Traceback" not in out
        assert "vendored amendment manifest, not the hook" in out
        assert "x-inspect-net amendments" in out

    def test_an_unparseable_macro_file_is_rendered_as_the_checkout_s_problem(
        self, monkeypatch, capsys, hook_artifact
    ):
        import hookz.wasm.whitelist as wl

        def _boom(*a, **k):
            raise wl.WhitelistError("hook_api.macro: parsed 75, file has 76")

        monkeypatch.setattr(wl, "get_import_signatures", _boom)

        art = hook_artifact

        code, out = self._main(["guard-check", str(art)], monkeypatch, capsys)

        assert code == 1
        assert "Traceback" not in out
        assert "configured xahaud checkout, not the hook" in out

    def test_both_are_value_errors_so_old_callers_still_catch_them(self):
        """Subclassing ValueError is what keeps `resolve_rules` degrading to
        0x00 with a warning rather than failing — the behaviour `doctor`
        depends on."""
        import hookz.amendments as amd
        import hookz.wasm.whitelist as wl

        assert issubclass(amd.ManifestError, ValueError)
        assert issubclass(wl.WhitelistError, ValueError)
