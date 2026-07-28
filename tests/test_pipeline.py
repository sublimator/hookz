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

from hookz.compiler import compile_hook
from hookz.config import load_config
from hookz.wasm.clean import clean_hook
from hookz.wasm.guard import analyze_wce
from hookz.wasm.optimize import (
    BUILDBOX, NONE, OPT_PROFILES, OptProfile, WasmOptError, get_opt_profile,
)
from hookz.wasm.pipeline import (
    BUILD_PIPELINES, BUILDBOX_PIPELINE, DEBUG_PIPELINE, DEFAULT_PIPELINE,
    get_pipeline, run_pipeline,
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

    def test_unknown_name_lists_the_known_ones(self):
        with pytest.raises(WasmOptError, match="buildbox"):
            get_opt_profile("no-such-profile")

    def test_registry_keys_match_profile_names(self):
        assert all(k == p.name for k, p in OPT_PROFILES.items())


# ---------------------------------------------------------------------------
# Running a pipeline
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_buildbox_is_the_default(self):
        assert DEFAULT_PIPELINE is BUILDBOX_PIPELINE

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

    def test_accepts_a_pipeline_by_name(self):
        assert run_pipeline(GOVERN, "buildbox").pipeline is BUILDBOX_PIPELINE

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
