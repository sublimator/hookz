"""Tests for the build pipeline — hookz.wasm.pipeline and .optimize.

The bug these exist for: hookz once shipped a wasm-opt profile missing
--rereloop. Every stage ran, every check passed, and the reported block depth
was one the deployed toolchain never produces — so a hook live on mainnet
measured 22 against a limit of 16 and was written up as un-installable.

Nothing here asserts a depth is *good*. They assert hookz runs what the
reference toolchain runs, and that the trace says what happened.
"""

from pathlib import Path

import pytest

from conftest import needs_compile
from hookz.compiler import compile_hook
from hookz.config import load_config
from hookz.wasm.clean import clean_hook
from hookz.wasm.guard import analyze_wce
from hookz.wasm.optimize import (
    BUILDBOX,
    LOCAL_STRUCTURAL,
    NONE,
    OPT_PROFILES,
    OptProfile,
    WasmOptError,
    get_opt_profile,
)
from hookz.wasm.pipeline import (
    BUILD_PIPELINES,
    BUILDBOX_PIPELINE,
    DEBUG_PIPELINE,
    DEFAULT_PIPELINE,
    LOCAL_STRUCTURAL_PIPELINE,
    get_pipeline,
    run_pipeline,
)

HOOKS = Path(__file__).parent / "e2e" / "hooks"
# 815 lines — the deepest-nesting hook in the tree, so --rereloop has something
# to restructure. On a trivial hook the ablation below is vacuous.
GOVERN = HOOKS / "genesis" / "govern.c"


@pytest.fixture(scope="module")
def govern_raw() -> bytes:
    """govern.c through the buildbox front end, before any wasm-opt."""
    cfg = load_config(source_file=GOVERN)
    return compile_hook(GOVERN, None, cfg, debug=False,
                        opt_level="-O3", export_all=True)


def _depth(wasm: bytes) -> int:
    return analyze_wce(wasm).max_depth


# ---------------------------------------------------------------------------
# Depth measurement
# ---------------------------------------------------------------------------

class TestDepth:
    """BlockInfo.depth counts the way _compute_wce's `level` does."""

    def test_synthetic_nesting_is_measured_exactly(self):
        from test_wasm import _nested_blocks_wasm

        for n in (1, 5, 17, 40):
            assert _depth(_nested_blocks_wasm(n)) == n

    def test_max_depth_is_zero_without_trees(self):
        from hookz.wasm.guard import GuardResult

        r = GuardResult(hook_wce=0, cbak_wce=0, import_count=0,
                        guard_func_idx=0, hook_func_idx=0, cbak_func_idx=None)
        assert r.max_depth == 0

    def test_depth_agrees_with_the_limit_verdict(self):
        """Tripping nesting_exceeded and measuring depth must not disagree."""
        from test_wasm import _nested_blocks_wasm
        from hookz.wasm.guard import nesting_limit

        limit = nesting_limit()
        for n in (limit - 1, limit, limit + 1, limit + 8):
            r = analyze_wce(_nested_blocks_wasm(n))
            assert r.max_depth == n
            assert r.nesting_exceeded == (n > limit)


# ---------------------------------------------------------------------------
# Profile invariants
# ---------------------------------------------------------------------------

class TestBuildboxProfile:
    def test_carries_rereloop(self):
        """The pass whose absence caused a live hook to read as un-installable."""
        assert "--rereloop" in BUILDBOX.passes

    def test_flatten_precedes_rereloop(self):
        """--rereloop requires flat IR; wasm-opt aborts otherwise."""
        p = list(BUILDBOX.passes)
        assert p.index("--flatten") < p.index("--rereloop")

    def test_matches_the_reference_flag_list(self):
        """Verbatim from chooks.ts @ COMPILER_COMMIT. See compiler_ref."""
        assert BUILDBOX.passes == (
            "--shrink-level=100000000", "--coalesce-locals-learning",
            "--vacuum", "--merge-blocks", "--merge-locals", "--flatten",
            "--ignore-implicit-traps", "-ffm", "--const-hoisting",
            "--code-folding", "--code-pushing", "--dae-optimizing", "--dce",
            "--simplify-globals-optimizing", "--simplify-locals-nonesting",
            "--reorder-locals", "--rereloop", "--precompute-propagate",
            "--local-cse", "--remove-unused-brs", "--memory-packing", "-c",
            "--avoid-reinterprets", "-O3",
        )

    def test_cites_its_source(self):
        from hookz.wasm import compiler_ref

        assert compiler_ref.COMPILER_COMMIT[:8] in BUILDBOX.provenance

    def test_rereloop_changes_the_reported_depth(self, govern_raw):
        """Non-vacuous: dropping it yields a different answer, not the same one.

        Direction is deliberately unasserted — the Relooper restructures rather
        than flattens, and costs a level or two on small hooks while collapsing
        large ones. What matters is that the pass is not inert, so a profile
        that silently loses it cannot pass these tests.
        """
        without = OptProfile(
            name="ablated", summary="", provenance="",
            invocations=(tuple(f for f in BUILDBOX.passes if f != "--rereloop"),),
        )
        assert _depth(clean_hook(BUILDBOX.run(govern_raw))) != \
            _depth(clean_hook(without.run(govern_raw)))

    def test_rereloop_needs_flat_ir(self, govern_raw):
        """Guards the ordering invariant above with the actual failure."""
        with pytest.raises(WasmOptError, match="[Ff]lat"):
            OptProfile(name="x", summary="", provenance="",
                       invocations=(("--rereloop",),)).run(govern_raw)


class TestProfileRegistry:
    def test_none_profile_is_a_passthrough(self, govern_raw):
        assert NONE.run(govern_raw) == govern_raw

    def test_lookup_by_name(self):
        assert get_opt_profile("buildbox") is BUILDBOX
        assert get_opt_profile("local-structural") is LOCAL_STRUCTURAL
        assert BUILDBOX.name == "local-structural"

    def test_unknown_name_lists_the_known_ones(self):
        with pytest.raises(WasmOptError, match="buildbox"):
            get_opt_profile("no-such-profile")

    def test_registry_keys_match_profile_names(self):
        assert all(k == p.name for k, p in OPT_PROFILES.items())


# ---------------------------------------------------------------------------
# Running a pipeline
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_local_structural_is_the_default(self):
        assert DEFAULT_PIPELINE is LOCAL_STRUCTURAL_PIPELINE

    def test_records_every_stage_in_order(self):
        trace = run_pipeline(GOVERN, BUILDBOX_PIPELINE)
        assert [s.name for s in trace.stages] == [
            "transform", "compile", "wasm-opt", "clean"]

    def test_final_stage_matches_the_artifact(self):
        trace = run_pipeline(GOVERN, BUILDBOX_PIPELINE)
        assert trace.final.size == len(trace.wasm)

    def test_wasm_stages_carry_depth_and_wce(self):
        """Source stages have no wasm to measure; every later stage must."""
        trace = run_pipeline(GOVERN, BUILDBOX_PIPELINE)
        for s in trace.stages:
            if s.name == "transform":
                continue
            assert s.depth is not None, f"{s.name}: {s.note}"
            assert s.hook_wce is not None, f"{s.name}: {s.note}"

    def test_result_is_deployable(self):
        """The whole point: what comes out passes the real guard checker."""
        from hookz.wasm.guard import validate_guards

        trace = run_pipeline(GOVERN, BUILDBOX_PIPELINE)
        assert validate_guards(trace.wasm).deployable

    def test_debug_pipeline_skips_optimize_and_clean(self):
        trace = run_pipeline(GOVERN, DEBUG_PIPELINE)
        assert [s.name for s in trace.stages] == ["compile"]

    def test_accepts_canonical_local_pipeline_name(self):
        assert run_pipeline(
            GOVERN, "local-structural"
        ).pipeline is LOCAL_STRUCTURAL_PIPELINE

    def test_old_buildbox_name_is_a_local_compatibility_alias(self):
        assert run_pipeline(GOVERN, "buildbox").pipeline is BUILDBOX_PIPELINE
        assert BUILDBOX_PIPELINE.name == "local-structural"

    def test_unknown_pipeline_lists_the_known_ones(self):
        with pytest.raises(ValueError, match="buildbox"):
            get_pipeline("no-such-pipeline")

    def test_registry_keys_match_pipeline_names(self):
        assert all(k == p.name for k, p in BUILD_PIPELINES.items())


class TestTraceTable:
    def test_table_has_a_row_per_stage(self):
        trace = run_pipeline(GOVERN, BUILDBOX_PIPELINE)
        lines = trace.format_table().splitlines()
        # header + rule + one per stage
        assert len(lines) == len(trace.stages) + 2

    def test_table_names_every_stage(self):
        trace = run_pipeline(GOVERN, BUILDBOX_PIPELINE)
        table = trace.format_table()
        assert all(s.name in table for s in trace.stages)


# ---------------------------------------------------------------------------
# The front end
# ---------------------------------------------------------------------------

class TestCompileSpec:
    def test_export_all_roots_more_functions(self):
        """--export-all changes what the optimizer may delete, not just names."""
        cfg = load_config(source_file=GOVERN)
        named = compile_hook(GOVERN, None, cfg, debug=False,
                             opt_level="-O3", export_all=False)
        every = compile_hook(GOVERN, None, cfg, debug=False,
                             opt_level="-O3", export_all=True)
        assert len(every) > len(named)

    def test_opt_level_overrides_the_optimize_flag(self):
        cfg = load_config(source_file=GOVERN)
        o0 = compile_hook(GOVERN, None, cfg, debug=False,
                          optimize=True, opt_level="-O0")
        o3 = compile_hook(GOVERN, None, cfg, debug=False,
                          optimize=True, opt_level="-O3")
        assert len(o0) != len(o3)


class TestTransformPolicy:
    """Which builds strip annotations, and which must not.

    Coverage keeping its annotations was correct and accidental — it reached
    clang by a different route, so the default pipeline's transform never
    applied. These pin the decision so the next transform lands deliberately.
    """

    def test_a_deployable_build_strips(self):
        from hookz.wasm.pipeline import BUILDBOX_PIPELINE

        assert BUILDBOX_PIPELINE.transforms == ("hookz.annotations:strip",)

    def test_an_analysis_build_does_not(self):
        """DWARF must point at the file a human is reading."""
        from hookz.wasm.pipeline import ANALYSIS_PIPELINE

        assert ANALYSIS_PIPELINE.transforms == ()
        assert ANALYSIS_PIPELINE.compile.debug

    def test_a_dev_build_does_not(self):
        """`hookz:` directives are rendered into code, not stripped out."""
        from hookz.wasm.pipeline import DEBUG_PIPELINE

        assert DEBUG_PIPELINE.transforms == ()

    def test_dev_mode_suppresses_transforms_even_when_declared(self):
        """run_pipeline(dev=True) must not strip the directives it is rendering."""
        from pathlib import Path

        from hookz.config import load_config
        from hookz.wasm.pipeline import run_pipeline

        source = Path(__file__).parent / "e2e" / "hooks" / "misc" / "balance_gate.c"
        trace = run_pipeline(source, "buildbox", load_config(source_file=source),
                             dev=True)
        assert "transform" not in [s.name for s in trace.stages]


def _write_hook_with_sibling_header(tmp_path, preamble: str = "") -> None:
    """A hook whose guard import is DECLARED IN THE SIBLING HEADER.

    That placement is the point: if the `#include` fails to resolve the
    compile dies, and if it resolves but the header were ignored the cleaner
    rejects the result for having no `_g` import. Either way the test fails
    for the reason it is named after.
    """
    (tmp_path / "helper.h").write_text(
        "#define HELPER_RESULT 7\n"
        "extern int64_t _g(uint32_t, uint32_t);\n"
    )
    (tmp_path / "hook.c").write_text(
        preamble
        + '#include <stdint.h>\n'
        '#include "helper.h"\n'
        'int64_t hook(uint32_t r) {\n'
        '    for (int i = 0; _g(1, 2), i < 1; ++i) { }\n'
        '    return HELPER_RESULT;\n'
        '}\n'
        'int64_t cbak(uint32_t r) { return 0; }\n'
    )


class TestTransformedBuildsKeepTheirIncludes:
    """A transform writes the source somewhere else, and clang resolves
    `#include "x.h"` relative to the *including file*. Somewhere else is a
    temp dir, so a stripping pipeline broke every hook with a sibling header
    while the un-transformed path kept working."""

    @needs_compile
    def test_a_sibling_header_still_resolves_after_stripping(self, tmp_path):
        from hookz.config import load_config
        from hookz.wasm.pipeline import (
            LOCAL_STRUCTURAL_PIPELINE, STRIP_ANNOTATIONS, run_pipeline,
        )

        assert STRIP_ANNOTATIONS in LOCAL_STRUCTURAL_PIPELINE.transforms, \
            "this test is only meaningful for a pipeline that relocates source"

        _write_hook_with_sibling_header(
            tmp_path,
            preamble="//@@ an annotation, so the strip transform has work to do\n",
        )
        source = tmp_path / "hook.c"

        trace = run_pipeline(source, LOCAL_STRUCTURAL_PIPELINE,
                             load_config(source_file=source))

        assert "transform" in [s.name for s in trace.stages]
        assert trace.wasm.startswith(b"\x00asm")

    @needs_compile
    def test_the_untransformed_path_is_unaffected(self, tmp_path):
        """The control: the same file through a pipeline that does not
        relocate it. If this fails the fixture is wrong, not the fix."""
        from hookz.config import load_config
        from hookz.wasm.pipeline import DEBUG_PIPELINE, run_pipeline

        _write_hook_with_sibling_header(tmp_path)
        source = tmp_path / "hook.c"

        trace = run_pipeline(source, DEBUG_PIPELINE,
                             load_config(source_file=source))

        assert trace.wasm.startswith(b"\x00asm")
