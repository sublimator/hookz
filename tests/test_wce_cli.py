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
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from hookz.cli.main import _annotated_line_map, _line_from_guard_id, cli
from hookz.wasm.guard import BlockInfo, GuardError, GuardResult
from hookz.wasm.pipeline import STRIP_ANNOTATIONS


WASM = b"\x00asm\x01\x00\x00\x00exact-artifact"

# One annotation line up front, so every published line sits one line lower in
# the annotated file: published 42 is annotated 43.
ANNOTATED_C = "//@@ model\n" + "\n" * 41 + "int hook;\n"


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


def fake_trace(*, name="local-structural", transforms=(STRIP_ANNOTATIONS,)):
    return SimpleNamespace(
        wasm=WASM,
        pipeline=SimpleNamespace(
            name=name,
            summary="local structural approximation",
            transforms=transforms,
        ),
        format_table=lambda: "stage   bytes\ncompile    22",
    )


def explode(message):
    def boom(*a, **k):
        raise AssertionError(message)

    return boom


@pytest.fixture
def local_build(monkeypatch):
    """Stub the local pipeline; return the recorder of what it was asked for."""
    seen = []
    trace = fake_trace()
    monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
    monkeypatch.setattr(
        "hookz.wasm.pipeline.run_pipeline",
        lambda path, pipeline, config: seen.append(pipeline) or trace,
    )
    monkeypatch.setattr("hookz.wasm.guard.validate_guards", lambda wasm: result())
    return SimpleNamespace(seen=seen, trace=trace)


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
            "hookz.wasm.guard.validate_guards", lambda wasm: result()
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

    def test_byte_count_is_the_weighed_artifact(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: result()
        )

        out = run(artifact)

        assert f"bytes: {len(WASM):,}" in out.output

    def test_loop_rows_are_opt_in(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: result_with_loop()
        )

        out = run(artifact)

        assert out.exit_code == 0, out.output
        assert "partial mapping" not in out.output
        assert "GUARD(" not in out.output

    def test_loop_mapping_is_separate_and_labeled_partial(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: result_with_loop()
        )

        out = run(artifact, "--loops")

        assert out.exit_code == 0, out.output
        assert "partial mapping" in out.output
        assert "line 42" in out.output
        assert "not additive" in out.output

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
            "hookz.wasm.guard.validate_guards", lambda wasm: result()
        )

        out = run(shouty)

        assert out.exit_code == 0, out.output
        assert "provided artifact" in out.output

    def test_rejected_artifact_is_nonzero_and_keeps_best_effort_totals(
        self, artifact, monkeypatch
    ):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: (_ for _ in ()).throw(GuardError("too deep")),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.analyze_wce", lambda wasm: result(hook=999)
        )

        out = run(artifact)

        assert out.exit_code == 1
        assert "DEPLOYABILITY: REJECTED" in out.output
        assert "too deep" in out.output
        assert "hook() WCE: 999" in out.output

    def test_over_depth_totals_are_declared_a_floor(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: (_ for _ in ()).throw(GuardError("nesting")),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.analyze_wce",
            lambda wasm: result(hook=999, nesting_exceeded=True),
        )

        out = run(artifact)

        assert out.exit_code == 1
        assert "floor" in out.output

    def test_warnings_are_surfaced_not_swallowed(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: result(errors=["No _g import found"]),
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

    def test_stage_table_is_shown_for_a_local_build(self, c_source, local_build):
        out = run(c_source)

        assert "compile" in out.output

    def test_named_pipeline_reaches_the_runner(self, c_source, local_build):
        out = run(c_source, "--pipeline", "analysis")

        assert out.exit_code == 0, out.output
        assert local_build.seen[0] is not None
        assert local_build.seen[0].name == "analysis"

    def test_unknown_pipeline_fails_with_the_runner_error(
        self, c_source, monkeypatch
    ):
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())

        out = run(c_source, "--pipeline", "no-such-pipeline")

        assert out.exit_code == 1
        assert "local pipeline failed" in out.output

    def test_buildbox_weighs_the_exact_remote_result(self, c_source, monkeypatch):
        remote = SimpleNamespace(
            wasm=WASM,
            endpoint="https://compiler.example/api/build",
            request_sha256="a" * 64,
        )
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr("hookz.buildbox.compile_source", lambda *a, **k: remote)
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline",
            explode("buildbox mode used local pipeline"),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: result()
        )

        out = run(c_source, "--buildbox")

        assert out.exit_code == 0, out.output
        assert "canonical buildbox result" in out.output
        assert "a" * 64 in out.output

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
            "hookz.wasm.guard.validate_guards", lambda wasm: result()
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
            "hookz.wasm.guard.validate_guards", lambda wasm: result()
        )

        out = run(artifact)

        assert out.exit_code == 0, out.output
        assert "provided artifact" in out.output

    def test_explicit_compiler_flags_on_a_wasm_are_still_refused(self, artifact):
        out = run(artifact, "--buildbox")

        assert out.exit_code == 2
        assert "already the artifact" in out.output


class TestGuardLineProvenance:
    """A guard id is a __LINE__ from whatever file clang saw."""

    def test_stripping_build_maps_the_artifact_line_into_the_annotated_file(
        self, tmp_path, monkeypatch
    ):
        source = tmp_path / "hook.c"
        source.write_text(ANNOTATED_C)
        monkeypatch.setattr("hookz.config.load_config", lambda **k: object())
        monkeypatch.setattr(
            "hookz.wasm.pipeline.run_pipeline", lambda *a, **k: fake_trace()
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: result_with_loop()
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
            lambda *a, **k: fake_trace(name="analysis", transforms=()),
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: result_with_loop()
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
            "hookz.wasm.guard.validate_guards", lambda wasm: result_with_loop()
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
            "hookz.wasm.pipeline.run_pipeline", lambda *a, **k: fake_trace()
        )
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards", lambda wasm: loopy
        )
        monkeypatch.setattr(type(source), "read_text", counting_read_text)

        out = run(source, "--loops")

        assert out.exit_code == 0, out.output
        assert len([p for p in reads if p == source]) == 1


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


class TestCbakIsReportedOnlyWhenItExists:
    def test_a_hook_without_cbak_prints_no_cbak_row(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: result(cbak=0, cbak_idx=None),
        )

        out = run(artifact)

        assert "hook() WCE" in out.output
        assert "cbak()" not in out.output

    def test_a_present_cbak_is_reported_even_at_zero(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: result(cbak=0, cbak_idx=2),
        )

        out = run(artifact)

        assert "cbak() WCE: 0" in out.output

    def test_cbak_cost_is_reported_next_to_hook(self, artifact, monkeypatch):
        monkeypatch.setattr(
            "hookz.wasm.guard.validate_guards",
            lambda wasm: result(hook=100, cbak=200),
        )

        out = run(artifact)

        assert "hook() WCE: 100" in out.output
        assert "cbak() WCE: 200" in out.output
