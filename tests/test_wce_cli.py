"""The WCE CLI must weigh the artifact it claims to judge.

Three things this file pins, because each one is a way for the report to be
confidently wrong rather than merely unhelpful:

  * the bytes weighed are the bytes named (sha256, provenance, no silent
    recompilation of a supplied .wasm);
  * a guard id is only translated into annotated-source coordinates when the
    build that produced it stripped annotations first;
  * absence is printed as absence — a missing cbak is not a free cbak.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from hookz.cli.main import _annotated_line_map, _line_from_guard_id, cli
from hookz.wasm.guard import BlockInfo, GuardError, GuardResult
from hookz.wasm.pipeline import (
    ANALYSIS_PIPELINE,
    DEBUG_PIPELINE,
    LOCAL_STRUCTURAL_PIPELINE,
    STRIP_ANNOTATIONS,
    BuildTrace,
    StageMetrics,
)


WASM = b"\x00asm\x01\x00\x00\x00exact-artifact"

# One annotation line up front, so every published line sits one line lower in
# the annotated file: published 42 is annotated 43.
ANNOTATED_C = "//@@ model\n" + "\n" * 41 + "int hook;\n"


@pytest.fixture(autouse=True)
def pinned_terminal_width(monkeypatch):
    """`wce` builds its own Console, which takes its width from COLUMNS when
    stdout is not a tty. Unpinned, every substring assertion in this file
    passes or fails on the window size of whoever runs it: at 120 the
    provenance line wraps mid-phrase, at 60 the sha256 splits in two.
    """
    monkeypatch.setenv("COLUMNS", "200")


def result(*, hook=123, cbak=4, cbak_idx=2, **kw):
    return GuardResult(
        hook_wce=hook,
        cbak_wce=cbak,
        import_count=1,
        guard_func_idx=0,
        hook_func_idx=1,
        cbak_func_idx=cbak_idx,
        **kw,
    )


def result_with_loop(*, guard_id=42, **kw):
    tree = BlockInfo(iteration_bound=1)
    loop = tree.add_child(
        5, 10, is_loop=True, guard_id=guard_id, guard_canonical=True
    )
    loop.instruction_count = 3
    value = result(hook=15, **kw)
    value.hook_tree = tree
    return value


def build_trace(pipeline=LOCAL_STRUCTURAL_PIPELINE, *, source_path=None):
    """A real BuildTrace carrying the real pipeline objects.

    Invented stand-ins drift: a SimpleNamespace whose `summary` was shorter
    than the genuine one made the provenance line fit on one rendered row,
    which is not a property the real pipeline has.
    """
    return BuildTrace(
        pipeline=pipeline,
        source_path=source_path or Path("hook.c"),
        wasm=WASM,
        stages=[
            StageMetrics(
                name="compile", detail="clang -O3", size=len(WASM) + 400, depth=3
            ),
            StageMetrics(
                name="clean",
                detail="hook-cleaner",
                size=len(WASM),
                depth=3,
                hook_wce=123,
            ),
        ],
    )


def explode(message):
    def boom(*a, **k):
        raise AssertionError(message)

    return boom


@pytest.fixture
def local_build(monkeypatch):
    """Stub the local pipeline; return the recorder of what it was asked for."""
    seen = []
    trace = build_trace()
    monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
    monkeypatch.setattr(
        "hookz.wasm.pipeline.run_pipeline",
        lambda path, pipeline, config: seen.append(pipeline) or trace,
    )
    monkeypatch.setattr("hookz.wasm.guard.validate_guards", lambda wasm, **kw: result())
    return SimpleNamespace(seen=seen, trace=trace)


@pytest.fixture
def buildbox(monkeypatch):
    """Stub the remote compiler, recording exactly what it was asked to build."""
    calls = []
    remote = SimpleNamespace(
        wasm=WASM,
        endpoint="https://compiler.example/api/build",
        request_sha256="a" * 64,
    )

    def compile_source(*a, **k):
        calls.append((a, k))
        return remote

    monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
    monkeypatch.setattr("hookz.buildbox.compile_source", compile_source)
    monkeypatch.setattr(
        "hookz.wasm.pipeline.run_pipeline",
        explode("buildbox mode used the local pipeline"),
    )
    monkeypatch.setattr("hookz.wasm.guard.validate_guards", lambda wasm, **kw: result())
    return SimpleNamespace(calls=calls, remote=remote)


@pytest.fixture
def c_source(tmp_path):
    source = tmp_path / "hook.c"
    source.write_text("int hook(void) { return 0; }\n")
    return source


@pytest.fixture
def artifact(tmp_path):
    path = tmp_path / "hook.wasm"
    path.write_bytes(WASM)
    return path


def run(*args):
    return CliRunner().invoke(cli, ["wce", *[str(a) for a in args]])


class TestExactArtifactFirst:
    def test_wasm_is_read_directly_and_never_compiled(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            explode("exact wasm was recompiled"),
        )

        out = run(artifact)

        assert out.exit_code == 0, out.output
        assert "provided artifact" in out.output
        assert hashlib.sha256(WASM).hexdigest() in out.output
        assert "hook() WCE: 123" in out.output
        assert "DEPLOYABILITY: PASSED" in out.output

    def test_byte_count_is_the_artifact_not_the_input_file(
        self, c_source, local_build
    ):
        """On a .wasm the two are the same number, so the claim only has
        content when the input is C: 29 bytes of source, 22 of artifact."""
        assert c_source.stat().st_size != len(WASM)

        out = run(c_source)

        assert f"bytes: {len(WASM):,}" in out.output
        assert f"bytes: {c_source.stat().st_size:,}" not in out.output

    def test_loop_rows_are_opt_in(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result_with_loop()
        )

        out = run(artifact)

        assert out.exit_code == 0, out.output
        assert "partial mapping" not in out.output
        assert "GUARD(" not in out.output

    def test_loop_mapping_is_separate_and_labeled_partial(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result_with_loop()
        )

        out = run(artifact, "--loops")

        assert out.exit_code == 0, out.output
        assert "partial mapping" in out.output
        assert "line 42" in out.output
        assert "not additive" in out.output

    def test_the_costliest_loop_is_listed_first(self, artifact, monkeypatch):
        """The list is a triage order. Reversed, it points at the cheapest
        loop first and reads exactly as authoritative."""
        tree = BlockInfo(iteration_bound=1)
        for guard, cost in ((11, 1), (22, 9), (33, 4)):
            child = tree.add_child(3, guard, is_loop=True, guard_id=guard)
            child.instruction_count = cost
        value = result(hook=50)
        value.hook_tree = tree
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: value
        )

        out = run(artifact, "--loops")

        cited = [
            int(ln.split("line ")[1].split()[0])
            for ln in out.output.splitlines()
            if "GUARD(" in ln
        ]
        assert cited == [22, 33, 11]

    def test_cbak_loops_are_reported_too(self, artifact, monkeypatch):
        """Loop rows have only ever been exercised on the hook side."""
        value = result_with_loop()
        cbak_tree = BlockInfo(iteration_bound=1)
        cbak_tree.add_child(
            7, 90, is_loop=True, guard_id=90
        ).instruction_count = 2
        value.cbak_tree = cbak_tree
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: value
        )

        out = run(artifact, "--loops")

        assert "line 42" in out.output  # hook side
        assert "line 90" in out.output  # cbak side
        assert "GUARD(7    )" in out.output

    def test_bytes_that_are_not_wasm_are_refused_not_analysed(
        self, tmp_path, monkeypatch
    ):
        impostor = tmp_path / "hook.wasm"
        impostor.write_bytes(b"#include <stdint.h>\n")
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", explode("decoded a non-module")
        )

        out = run(impostor)

        assert out.exit_code == 1
        assert "not a WebAssembly 1 module" in out.output

    def test_input_must_declare_which_kind_it_is(self, tmp_path):
        mystery = tmp_path / "hook.bin"
        mystery.write_bytes(WASM)

        out = run(mystery)

        assert out.exit_code == 2
        assert "must end in .c or .wasm" in out.output

    def test_suffix_matching_is_case_insensitive(self, tmp_path, monkeypatch):
        shouty = tmp_path / "HOOK.WASM"
        shouty.write_bytes(WASM)
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(shouty)

        assert out.exit_code == 0, out.output
        assert "provided artifact" in out.output

    def test_rejected_artifact_is_nonzero_and_keeps_best_effort_totals(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: (_ for _ in ()).throw(GuardError("too deep")),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.analyze_wce", lambda wasm, **kw: result(hook=999)
        )

        out = run(artifact)

        assert out.exit_code == 1
        assert "DEPLOYABILITY: REJECTED" in out.output
        assert "too deep" in out.output
        assert "hook() WCE: 999" in out.output
        # This rejection is not a depth one, so the total is exact. Calling
        # every rejected total a floor would be its own false statement.
        assert "floor" not in out.output

    def test_over_depth_totals_are_declared_a_floor(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: (_ for _ in ()).throw(GuardError("nesting")),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.analyze_wce",
            lambda wasm, **kw: result(hook=999, nesting_exceeded=True),
        )

        out = run(artifact)

        assert out.exit_code == 1
        assert "floor" in out.output

    def test_warnings_are_surfaced_not_swallowed(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: result(errors=["No _g import found"]),
        )

        out = run(artifact)

        assert "1 warning(s)" in out.output
        assert "No _g import found" in out.output

    def test_standalone_wasm_refuses_a_fake_source_view(self, artifact):
        out = run(artifact, "--source")

        assert out.exit_code == 2
        assert "no verified source twin" in out.output


class TestSourceCompilationChoice:
    def test_c_defaults_to_the_local_production_like_pipeline(
        self, c_source, local_build
    ):
        out = run(c_source)

        assert out.exit_code == 0, out.output
        assert local_build.seen == [None]
        assert "production-like approximation, not buildbox provenance" in out.output
        assert "exact-artifact WCE" in out.output

    def test_stage_table_describes_the_build_that_was_weighed(
        self, c_source, local_build
    ):
        """A trace printed for a different build than the one weighed would
        look perfectly consistent, so tie the last stage to the byte count."""
        out = run(c_source)

        assert "compile" in out.output
        assert "clean" in out.output
        final = local_build.trace.stages[-1]
        assert final.size == len(WASM)
        assert f"bytes: {final.size:,}" in out.output

    def test_named_pipeline_reaches_the_runner(self, c_source, local_build):
        out = run(c_source, "--pipeline", "analysis")

        assert out.exit_code == 0, out.output
        assert local_build.seen[0] is not None
        assert local_build.seen[0].name == "analysis"

    def test_unknown_pipeline_is_a_usage_error_naming_the_real_ones(
        self, c_source, monkeypatch
    ):
        """A name this flag will not take is bad usage, not a failed build —
        so it exits 2 and lists what it would have taken."""
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            explode("an unknown --pipeline name still started a build"),
        )

        out = run(c_source, "--pipeline", "no-such-pipeline")

        assert out.exit_code == 2
        assert "local-structural" in out.output
        assert "local pipeline failed" not in out.output

    def test_buildbox_weighs_the_exact_remote_result(self, c_source, buildbox):
        out = run(c_source, "--buildbox")

        assert out.exit_code == 0, out.output
        assert "canonical buildbox result" in out.output
        assert "a" * 64 in out.output

    def test_the_service_is_sent_this_source_under_this_name(
        self, c_source, buildbox
    ):
        """Stubbing compile_source and asserting only on the reply proves the
        report renders; it does not prove the right file was compiled."""
        run(c_source, "--buildbox")

        args, kwargs = buildbox.calls[0]
        assert args[0] == c_source.read_text()
        assert kwargs["filename"] == "hook.c"

    def test_buildbox_url_and_options_reach_the_request(self, c_source, buildbox):
        run(
            c_source,
            "--buildbox",
            "--buildbox-url",
            "https://elsewhere.example/api/build",
            "--buildbox-options",
            "-Oz",
        )

        _, kwargs = buildbox.calls[0]
        assert kwargs["endpoint"] == "https://elsewhere.example/api/build"
        assert kwargs["options"] == "-Oz"

    def test_default_compiler_options_are_the_documented_ones(
        self, c_source, buildbox
    ):
        run(c_source, "--buildbox")

        _, kwargs = buildbox.calls[0]
        assert kwargs["options"] == "-O3"
        assert kwargs["endpoint"] is None  # the client picks its own default

    def test_buildbox_failure_never_falls_back_to_a_local_compiler(
        self, c_source, monkeypatch
    ):
        from hookz.buildbox import BuildboxError

        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.buildbox.compile_source",
            lambda *a, **k: (_ for _ in ()).throw(BuildboxError("503")),
        )
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            explode("buildbox failure fell back to the local compiler"),
        )

        out = run(c_source, "--buildbox")

        assert out.exit_code == 1
        assert "buildbox failed: 503" in out.output

    def test_buildbox_and_local_pipeline_are_mutually_exclusive(self, c_source):
        out = run(c_source, "--buildbox", "--pipeline", "debug")

        assert out.exit_code == 2
        assert "cannot be combined" in out.output

    def test_pipeline_buildbox_is_refused_before_anything_runs(
        self, c_source, monkeypatch
    ):
        """It used to resolve to local-structural and weigh a local build.

        Asserted on both pointers rather than on `buildbox`, which is in the
        input and so would also match a bare "unknown pipeline". The exploding
        run_pipeline pins the *before*: a rejected spelling must not reach a
        build, and must not be reported as one that failed.
        """
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            explode("a refused --pipeline name still started a build"),
        )

        out = run(c_source, "--pipeline", "buildbox")

        assert out.exit_code == 2
        assert "--buildbox" in out.output
        assert "--pipeline local-structural" in out.output
        assert "local pipeline failed" not in out.output

    def test_buildbox_url_without_buildbox_is_refused(self, c_source):
        out = run(c_source, "--buildbox-url", "https://elsewhere.example")

        assert out.exit_code == 2
        assert "--buildbox-url requires --buildbox" in out.output

    def test_env_switch_selects_the_remote_compiler_for_c(
        self, c_source, monkeypatch
    ):
        remote = SimpleNamespace(
            wasm=WASM, endpoint="https://ci.example", request_sha256="b" * 64
        )
        monkeypatch.setenv("HOOKZ_BUILDBOX", "1")
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr("hookz.buildbox.compile_source", lambda *a, **k: remote)
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(c_source)

        assert out.exit_code == 0, out.output
        assert "canonical buildbox result" in out.output

    def test_env_switch_does_not_reject_a_prebuilt_artifact(
        self, artifact, monkeypatch
    ):
        """CI sets HOOKZ_BUILDBOX once per job; weighing a .wasm in that job
        must not become a usage error about compiler selection."""
        monkeypatch.setenv("HOOKZ_BUILDBOX", "1")
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(artifact)

        assert out.exit_code == 0, out.output
        assert "provided artifact" in out.output

    def test_an_explicit_pipeline_beats_the_env_switch(
        self, c_source, monkeypatch
    ):
        """CI sets HOOKZ_BUILDBOX once per job. Inside that job --pipeline must
        still work, and must not be refused by an error naming --buildbox,
        which is not on the command line."""
        seen = []
        monkeypatch.setenv("HOOKZ_BUILDBOX", "1")
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.buildbox.compile_source",
            explode("an explicit --pipeline still went to the buildbox"),
        )
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            lambda path, pipeline, config: seen.append(pipeline)
            or build_trace(ANALYSIS_PIPELINE),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(c_source, "--pipeline", "analysis")

        assert out.exit_code == 0, out.output
        assert seen[0].name == "analysis"

    def test_both_flags_typed_together_are_still_refused(self, c_source):
        """The mutual exclusion is between two things the user asked for."""
        out = run(c_source, "--buildbox", "--pipeline", "analysis")

        assert out.exit_code == 2
        assert "cannot be combined" in out.output

    def test_a_non_production_pipeline_is_not_called_production_like(
        self, c_source, monkeypatch
    ):
        """The debug pipeline's own summary says "for reading, not deploying".
        Appending "production-like approximation" to that is the label-over-
        the-numbers mistake this command was rewritten to stop making."""
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            lambda *a, **k: build_trace(DEBUG_PIPELINE),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(c_source, "--pipeline", "debug")

        assert out.exit_code == 0, out.output
        assert "NOT what you would deploy" in out.output
        assert "production-like" not in out.output

    def test_the_production_pipeline_still_says_it_is_not_the_buildbox(
        self, c_source, local_build
    ):
        out = run(c_source)

        assert "production-like approximation, not buildbox provenance" in out.output

    def test_a_failed_compile_is_reported_not_raised(self, c_source, monkeypatch):
        """clang failing is the most ordinary way for this command to fail,
        and RuntimeError was outside the caught set."""
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("Compilation failed:\nhook.c:3:1: error")
            ),
        )

        out = run(c_source)

        assert out.exit_code == 1
        assert "local pipeline failed" in out.output
        assert "hook.c:3:1: error" in out.output

    def test_explicit_compiler_flags_on_a_wasm_are_still_refused(self, artifact):
        out = run(artifact, "--buildbox")

        assert out.exit_code == 2
        assert "already the artifact" in out.output


class TestGuardLineProvenance:
    """A guard id is a __LINE__ from whatever file clang saw.

    Covers the two cases that exist: a build that stripped annotations and one
    that did not.

    TODO(guard-line-citation-provenance): two more are known and untested
    because nothing in-tree can reach them — a line-shifting transform declared
    alongside the stripper, and a guard whose __LINE__ comes from a header
    rather than the hook's own .c. Both print a citation that looks exactly
    like a correct one.
    """

    def test_stripping_build_maps_the_artifact_line_into_the_annotated_file(
        self, tmp_path, monkeypatch
    ):
        source = tmp_path / "hook.c"
        source.write_text(ANNOTATED_C)
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline", lambda *a, **k: build_trace()
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result_with_loop()
        )

        out = run(source, "--loops")

        assert out.exit_code == 0, out.output
        assert "line 43 (artifact 42)" in out.output

    def test_unstripped_build_cites_the_line_the_compiler_actually_saw(
        self, tmp_path, monkeypatch
    ):
        """The analysis pipeline keeps annotations, so its __LINE__ values are
        already annotated coordinates. Mapping them again lands on unrelated
        code and still reads as an answer."""
        source = tmp_path / "hook.c"
        source.write_text(ANNOTATED_C)
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            lambda *a, **k: build_trace(ANALYSIS_PIPELINE),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result_with_loop()
        )

        out = run(source, "--pipeline", "analysis", "--loops")

        assert out.exit_code == 0, out.output
        assert "line 42" in out.output
        assert "artifact 42" not in out.output

    def test_buildbox_result_is_mapped_because_the_service_gets_stripped_source(
        self, tmp_path, monkeypatch
    ):
        source = tmp_path / "hook.c"
        source.write_text(ANNOTATED_C)
        remote = SimpleNamespace(
            wasm=WASM, endpoint="https://compiler.example", request_sha256="c" * 64
        )
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr("hookz.buildbox.compile_source", lambda *a, **k: remote)
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result_with_loop()
        )

        out = run(source, "--buildbox", "--loops")

        assert out.exit_code == 0, out.output
        assert "line 43 (artifact 42)" in out.output

    def test_source_is_read_once_per_report_not_once_per_loop(
        self, tmp_path, monkeypatch
    ):
        source = tmp_path / "hook.c"
        source.write_text(ANNOTATED_C)
        tree = BlockInfo(iteration_bound=1)
        for guard in (42, 43, 44):
            tree.add_child(5, guard, is_loop=True, guard_id=guard).instruction_count = 1
        loopy = result(hook=15)
        loopy.hook_tree = tree

        reads = []
        original = type(source).read_text

        def counting_read_text(self, *a, **k):
            reads.append(self)
            return original(self, *a, **k)

        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline", lambda *a, **k: build_trace()
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: loopy
        )
        monkeypatch.setattr(type(source), "read_text", counting_read_text)

        out = run(source, "--loops")

        assert out.exit_code == 0, out.output
        assert len([p for p in reads if p == source]) == 1


class TestSecondarySourceView:
    """The --source block: two twin builds, wired to a panel whose two columns
    mean different things. Nothing here is artifact WCE, so the wiring is the
    only thing that can be right or wrong."""

    @pytest.fixture
    def twins(self, monkeypatch):
        """-Oz twin and debug twin, distinguishable by their DWARF row counts.

        The twin carries one row for line 1, the debug build two. A panel that
        reports 1 in the debug column has been handed the wrong build.
        """
        locs = {b"TWIN": [1], b"DEBUG": [1, 1]}

        monkeypatch.setattr(
            "hookz.compiler.compile_hook_two_stage",
            lambda source, config, opt_level=None: b"TWIN",
        )
        monkeypatch.setattr(
            "hookz.compiler.compile_hook",
            lambda source, config=None, debug=False, optimize=True: b"DEBUG",
        )
        monkeypatch.setattr(
            "hookz.wasm.clean.clean_hook_detailed",
            lambda wasm, visitor=None: SimpleNamespace(wasm=wasm),
        )
        monkeypatch.setattr(
            "hookz.coverage.rewriter.parse_dwarf_locations",
            lambda wasm, **kw: [SimpleNamespace(line=n) for n in locs[wasm]],
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.analyze_wce",
            lambda wasm, **kw: result(hook=7, cbak_idx=None),
        )

    @staticmethod
    def _cells(output, needle):
        row = next(ln for ln in output.splitlines() if needle in ln)
        return [c.strip() for c in row.split("│")]

    def test_the_panel_is_appended_after_the_exact_report(
        self, c_source, local_build, twins
    ):
        out = run(c_source, "--source")

        assert out.exit_code == 0, out.output
        assert "not artifact WCE" in out.output
        # order matters: the artifact verdict must not be buried under it
        assert out.output.index("DEPLOYABILITY") < out.output.index("Secondary")

    def test_each_column_reports_the_build_it_is_labelled_with(
        self, c_source, local_build, twins
    ):
        out = run(c_source, "--source")

        header = self._cells(out.output, "debug")
        row = self._cells(out.output, "int hook(void)")
        assert header[1] == "debug" and header[2] == "-Oz"
        # debug twin has 2 DWARF rows for this line, -Oz twin has 1
        assert row[1] == "2", f"debug column got {row[1]!r}"
        assert row[2] == "1", f"-Oz column got {row[2]!r}"

    def test_a_failed_twin_build_warns_instead_of_drawing_a_panel(
        self, c_source, local_build, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.compiler.compile_hook_two_stage",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no wasi-sdk")),
        )

        out = run(c_source, "--source")

        assert out.exit_code == 0, out.output
        assert "secondary source view unavailable: no wasi-sdk" in out.output
        assert "not artifact WCE" not in out.output

    def test_the_exact_verdict_still_decides_the_exit_code(
        self, c_source, monkeypatch, twins
    ):
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline", lambda *a, **k: build_trace()
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: (_ for _ in ()).throw(GuardError("too deep")),
        )

        out = run(c_source, "--source")

        assert out.exit_code == 1
        assert "DEPLOYABILITY: REJECTED" in out.output


class TestStripDeclarationIsRealNotJustAString:
    """The mapping decision reads pipeline.transforms, so the constant and the
    pipelines have to keep agreeing with the code that actually strips."""

    def test_the_named_transform_resolves_to_the_real_stripper(self):
        from hookz.annotations import strip
        from hookz.wasm.pipeline import _resolve_transform

        assert _resolve_transform(STRIP_ANNOTATIONS) is strip

    def test_the_production_like_pipeline_declares_it(self):
        from hookz.wasm.pipeline import LOCAL_STRUCTURAL_PIPELINE

        assert STRIP_ANNOTATIONS in LOCAL_STRUCTURAL_PIPELINE.transforms

    def test_the_analysis_pipeline_does_not(self):
        from hookz.wasm.pipeline import ANALYSIS_PIPELINE, DEBUG_PIPELINE

        assert STRIP_ANNOTATIONS not in ANALYSIS_PIPELINE.transforms
        assert STRIP_ANNOTATIONS not in DEBUG_PIPELINE.transforms


class TestGuardIdDecoding:
    def test_bit31_encoded_line(self):
        assert _line_from_guard_id((1 << 31) + 217) == "line 217"

    def test_signed_representation_of_the_same_id(self):
        assert _line_from_guard_id(-((1 << 31) - 217)) == "line 217"

    def test_raw_line_number(self):
        assert _line_from_guard_id(217) == "line 217"

    def test_an_id_that_is_not_a_plausible_line_stays_an_id(self):
        assert _line_from_guard_id(0xDEADBEEF).startswith("guard 0x")

    def test_zero_is_not_a_line(self):
        assert _line_from_guard_id(0) == "guard 0x00000000"

    def test_mapping_shows_both_coordinates(self):
        assert _line_from_guard_id(2, {2: 43}) == "line 43 (artifact 2)"

    def test_a_line_absent_from_the_map_is_left_alone(self):
        assert _line_from_guard_id(9, {2: 43}) == "line 9"

    def test_an_identity_mapping_adds_no_noise(self):
        assert _line_from_guard_id(2, {2: 2}) == "line 2"

    def test_annotated_line_map_inverts_published_to_annotated(self, tmp_path):
        source = tmp_path / "hook.c"
        source.write_text("//@@ why\nint a;\n//@@ because\nint b;\n")

        assert _annotated_line_map(source) == {1: 2, 2: 4}

    def test_annotated_line_map_of_the_shared_fixture(self, tmp_path):
        source = tmp_path / "hook.c"
        source.write_text(ANNOTATED_C)

        assert _annotated_line_map(source)[42] == 43


class TestAnEntryPointIsReportedOnlyWhenItExists:
    def test_a_hook_without_cbak_says_so_rather_than_costing_zero(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: result(cbak=0, cbak_idx=None),
        )

        out = run(artifact)

        assert "hook() WCE" in out.output
        assert "cbak() not exported" in out.output
        assert "cbak() WCE" not in out.output

    def test_a_missing_hook_export_is_not_a_free_hook_either(
        self, artifact, monkeypatch
    ):
        """A binary that exports no hook() is rejected, and `hook() WCE: 0`
        for an entry point that does not exist is the same falsehood."""
        broken = GuardResult(
            hook_wce=0, cbak_wce=0, import_count=1, guard_func_idx=0,
            hook_func_idx=-1, cbak_func_idx=2,
            errors=["No hook() export found"],
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: (_ for _ in ()).throw(GuardError("no hook export")),
        )
        monkeypatch.setattr("hookz.wasm.guard.analyze_wce", lambda wasm, **kw: broken)

        out = run(artifact)

        assert out.exit_code == 1
        assert "hook() not exported" in out.output
        assert "hook() WCE" not in out.output
        assert "cbak() WCE: 0" in out.output  # cbak IS exported

    def test_a_present_cbak_is_reported_even_at_zero(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: result(cbak=0, cbak_idx=2),
        )

        out = run(artifact)

        assert "cbak() WCE: 0" in out.output

    def test_cbak_cost_is_reported_next_to_hook(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: result(hook=100, cbak=200),
        )

        out = run(artifact)

        assert "hook() WCE: 100" in out.output
        assert "cbak() WCE: 200" in out.output


class TestErrorsReachTheUserAsErrors:
    """`main()` runs Click with standalone_mode=False, which stops Click
    catching — and therefore printing — its own exceptions. CliRunner defaults
    to standalone_mode=True, so the rest of this file cannot see the
    difference: every UsageError it asserts on was reaching the real binary as
    a traceback with the message on the last line.
    """

    @staticmethod
    def _run_main(argv, monkeypatch, capsys):
        from hookz.cli.main import main

        monkeypatch.setattr("sys.argv", ["hookz", *argv])
        try:
            main()
        except SystemExit as exc:
            return exc.code, capsys.readouterr()
        raise AssertionError("main() did not exit")

    def test_a_usage_error_prints_a_message_and_exits_2(
        self, artifact, monkeypatch, capsys
    ):
        code, out = self._run_main(
            ["wce", str(artifact), "--buildbox"], monkeypatch, capsys
        )

        assert code == 2
        assert "already the artifact" in out.err
        assert "Traceback" not in out.err

    def test_a_click_exception_prints_a_message_and_exits_1(
        self, c_source, monkeypatch, capsys
    ):
        """A build that starts and dies — clang failing is the ordinary case.

        Used to be driven by an unknown --pipeline name, which is now rejected
        as usage before any build starts and so exercises the exit-2 path
        above instead.

        Paired with that exit-2 test rather than redundant with it: UsageError
        subclasses ClickException, so both enter the same `except` arm in
        main(). What the pair pins is that main() exits with `exc.exit_code`
        rather than a constant — replacing it with either literal fails one of
        the two.
        """
        def _die(*a, **k):
            raise RuntimeError("clang: error: no such file")

        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr("hookz.wasm.pipeline.run_pipeline", _die)
        code, out = self._run_main(
            ["wce", str(c_source)], monkeypatch, capsys
        )

        assert code == 1
        assert "local pipeline failed" in out.err
        assert "clang: error" in out.err
        assert "Traceback" not in out.err

    def test_a_clean_run_still_exits_zero_through_main(
        self, artifact, monkeypatch, capsys
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        code, _ = self._run_main(["wce", str(artifact)], monkeypatch, capsys)

        assert code == 0


class TestUndecodableBytesGetAVerdictNotATraceback:
    def test_a_truncated_artifact_is_reported_not_raised(self, tmp_path):
        """analyze_wce is the rejection handler's fallback, so it is reached
        precisely when the bytes are already suspect. It promises never to
        raise; the decode was outside that promise."""
        from hookz.wasm.guard import analyze_wce

        truncated = WASM + b"\x0a\xff\xff\xff\xff\xff"
        outcome = analyze_wce(truncated)

        assert outcome.hook_func_idx == -1
        assert any("decode" in e.lower() for e in outcome.errors)

    def test_the_cli_reports_it_rather_than_dying_in_the_handler(self, tmp_path):
        artifact = tmp_path / "hook.wasm"
        artifact.write_bytes(WASM + b"\x0a\xff\xff\xff\xff\xff")

        out = run(artifact)

        assert out.exit_code == 1
        assert "DEPLOYABILITY: REJECTED" in out.output
        assert "hook() not exported" in out.output


class TestTheVerdictNamesItsRules:
    """A deployability verdict is only meaningful under stated rules, and the
    rules are a fact about the network rather than a constant."""

    def test_the_rules_and_the_limit_they_imply_are_printed(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(artifact)

        assert "rules: 0x01 (nesting limit 16)" in out.output

    def test_the_network_rules_are_what_reach_the_checker(
        self, artifact, monkeypatch
    ):
        import hookz.amendments as amd

        seen = {}

        def spy(wasm, **kw):
            seen.update(kw)
            return result()

        monkeypatch.setattr("hookz.wasm.guard.validate_guards", spy)

        run(artifact)

        assert seen["rules_version"] == amd.guard_rules_version()

    def test_depth32_is_an_override_and_says_so(self, artifact, monkeypatch):
        from hookz.wasm.guard import GUARD_RULE_DEPTH_32

        seen = {}

        def spy(wasm, **kw):
            seen.update(kw)
            return result()

        monkeypatch.setattr("hookz.wasm.guard.validate_guards", spy)

        out = run(artifact, "--depth32")

        assert seen["rules_version"] & GUARD_RULE_DEPTH_32
        assert "nesting limit 32" in out.output
        assert "--depth32 assumed" in out.output

    def test_without_the_override_nothing_claims_an_assumption(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm, **kw: result()
        )

        out = run(artifact)

        assert "assumed" not in out.output

    def test_waivers_reach_the_checker_too(self, artifact, monkeypatch):
        from hookz.wasm.guard import IGNORE_DEPTH

        seen = {}

        def spy(wasm, **kw):
            seen.update(kw)
            return result()

        monkeypatch.setattr("hookz.wasm.guard.validate_guards", spy)

        run(artifact, "--ignore-depth")

        assert IGNORE_DEPTH in seen["ignore"]

    def test_the_best_effort_path_gets_the_same_rules(
        self, artifact, monkeypatch
    ):
        """The rejected path is exactly when the depth verdict is in question,
        and it used to bound depth at 16 whatever the network ran."""
        seen = {}

        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm, **kw: (_ for _ in ()).throw(GuardError("too deep")),
        )

        def spy(wasm, **kw):
            seen.update(kw)
            return result(hook=9)

        monkeypatch.setattr("hookz.wasm.guard.analyze_wce", spy)

        run(artifact, "--depth32")

        from hookz.wasm.guard import GUARD_RULE_DEPTH_32

        assert seen["rules_version"] & GUARD_RULE_DEPTH_32
