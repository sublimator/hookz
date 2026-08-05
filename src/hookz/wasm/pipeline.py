"""The hook build pipeline — named toolchains, and a trace of what each did.

A hook's build is not an implementation detail: which flags run decides whether
xahaud's SetHook accepts the binary. The same source compiled two defensible
ways can differ by 8 levels of block nesting, which is the difference between
deploying and being rejected outright. So the toolchains are declared here
rather than assembled inline, each carrying the provenance of its flags, and
running one returns a BuildTrace recording size/depth/WCE after every stage.

    trace = run_pipeline(source)            → BuildTrace
    trace.wasm                              → the artifact
    trace.stages                            → what each stage did to it

Stage outputs also have individual types (CompileOutput, CleanOutput, …) for
callers driving the stages by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import compiler_ref
from .guard import GuardResult
from .optimize import LOCAL_STRUCTURAL, NONE, OptProfile


# ---------------------------------------------------------------------------
# Source map
# ---------------------------------------------------------------------------

@dataclass
class SourceMap:
    """Parsed source map (from -gsource-map or DWARF locations)."""

    # Core mapping: wasm byte offset → (file, line, col)
    mappings: list[tuple[int, str, int, int]]  # [(offset, file, line, col), ...]
    sources: list[str] = field(default_factory=list)

    def line_for_offset(self, offset: int) -> tuple[str, int, int] | None:
        """Find the source location for a WASM byte offset.

        Returns (file, line, col) or None.
        """
        best = None
        for map_offset, file, line, col in self.mappings:
            if map_offset <= offset:
                best = (file, line, col)
            elif map_offset > offset:
                break
        return best

    def offsets_for_line(self, line: int, file: str | None = None) -> list[int]:
        """Find all WASM byte offsets for a source line."""
        return [
            off for off, f, ln, _ in self.mappings
            if ln == line and (file is None or f == file)
        ]

    @staticmethod
    def from_json(data: dict) -> SourceMap:
        """Parse a standard source map JSON (version 3)."""
        sources = data.get("sources", [])
        # VLQ decode the "mappings" field
        mappings = _decode_source_map_mappings(
            data.get("mappings", ""), sources)
        return SourceMap(mappings=mappings, sources=sources)

    @staticmethod
    def from_dwarf_locs(locs: list) -> SourceMap:
        """Build a SourceMap from DWARF SourceLoc entries."""
        mappings = [(loc.address, "", loc.line, loc.col) for loc in locs]
        return SourceMap(mappings=mappings)


# ---------------------------------------------------------------------------
# Pipeline stage outputs
# ---------------------------------------------------------------------------

@dataclass
class CompileOutput:
    """Result of compilation."""
    wasm: bytes
    source_path: Path
    source_map: SourceMap | None = None
    debug: bool = False  # compiled with -g


@dataclass
class OptimizeOutput:
    """Result of wasm-opt optimization."""
    wasm: bytes
    source_path: Path
    source_map: SourceMap | None = None
    original_size: int = 0
    optimized_size: int = 0


@dataclass
class CleanOutput:
    """Result of hook cleaning."""
    wasm: bytes
    source_path: Path
    source_map: SourceMap | None = None
    relocations: list[tuple[int, int]] = field(default_factory=list)
    original_size: int = 0
    cleaned_size: int = 0


@dataclass
class GuardCheckOutput:
    """Result of guard validation."""
    wasm: bytes
    source_path: Path
    source_map: SourceMap | None = None
    result: GuardResult = field(default_factory=lambda: GuardResult(
        hook_wce=0, cbak_wce=0, import_count=0,
        guard_func_idx=0, hook_func_idx=0, cbak_func_idx=None,
    ))
    passed: bool = False


@dataclass
class WceOutput:
    """Result of WCE analysis."""
    result: GuardResult
    source_path: Path
    source_map: SourceMap | None = None

    # Per-line WCE breakdown: line → estimated cost
    line_costs: dict[int, int] = field(default_factory=dict)

    # Per-loop breakdown
    loops: list[LoopInfo] = field(default_factory=list)

    @property
    def hook_wce(self) -> int:
        return self.result.hook_wce

    @property
    def cbak_wce(self) -> int:
        return self.result.cbak_wce


@dataclass
class LoopInfo:
    """A single loop's contribution to WCE."""
    source_line: int
    source_file: str
    guard_id: int
    iteration_bound: int
    wce: int  # this loop's contribution
    depth: int  # nesting depth


# ---------------------------------------------------------------------------
# Named toolchains
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompileSpec:
    """The clang half of a pipeline."""

    opt_level: str
    debug: bool = False
    # xrpl-hooks-compiler links with --export-all and lets the cleaner strip
    # the surplus. That is not cosmetic: exporting everything roots every
    # function against DCE, so the optimizer sees a different module than it
    # does when only hook/cbak are exported.
    export_all: bool = False
    extra_flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class BuildPipeline:
    """A complete source → deployable-wasm toolchain."""

    name: str
    summary: str
    provenance: str
    compile: CompileSpec
    opt: OptProfile
    clean: bool = True
    # Source-to-source passes applied before clang, each named "module:function"
    # and taking str -> str. Hooks compile `__LINE__` into the binary, so a
    # transform that adds or removes a line changes the artifact; this is where
    # anything that rewrites source has to declare itself and show up in the
    # trace, rather than happening somewhere on the way in.
    #
    # TODO(guard-line-citation-provenance): declared, not enforced. Nothing
    # checks that a transform preserves line numbering, and `hookz wce --loops`
    # decides whether to map guard ids back into annotated coordinates by
    # testing for the stripper's *presence* here — so a line-shifting pass
    # declared alongside it would silently invalidate that mapping. Either
    # record the compiled text on the trace, or make line-preservation a
    # property a transform has to declare.
    transforms: tuple[str, ...] = ()

    @property
    def targets_production(self) -> bool:
        """Is this pipeline aiming at the artifact you would deploy?

        Derived rather than declared: the cleaner is what makes a hook
        installable at all — it strips custom sections, rebuilds exports and
        rewrites guards — so a pipeline that skips it is not producing a
        deployable candidate and must not be described as approximating one.
        """
        return self.clean


# Named, because whether a build stripped decides whether the artifact's
# __LINE__ values are published or annotated line numbers, and readers of the
# trace have to be able to ask.
STRIP_ANNOTATIONS = "hookz.annotations:strip"

# A local structural approximation using the historical web compiler's flags.
# It does not call the buildbox and is not byte-identical to it; the local
# clang, binaryen and cleaner differ. Provenance and known divergences:
# hookz.wasm.compiler_ref.
LOCAL_STRUCTURAL_PIPELINE = BuildPipeline(
    name="local-structural",
    summary="local structural approximation (clang -O3 → binaryen → cleaner)",
    provenance=f"{compiler_ref.COMPILER_SOURCE} @ "
               f"{compiler_ref.COMPILER_COMMIT[:8]} "
               f"({compiler_ref.COMPILER_COMMIT_DATE})",
    compile=CompileSpec(opt_level="-O3", export_all=True),
    opt=LOCAL_STRUCTURAL,
    # An annotated hook must build to the same bytes as the file it annotates,
    # or the analysis describes a binary nobody deployed.
    transforms=(STRIP_ANNOTATIONS,),
)

# Analysis builds — coverage, `hookz wce`, the instrumented hooks tests drive.
# They deliberately do NOT strip annotations, and the reason is not obvious:
# DWARF line numbers have to point at the file a human is reading, and a
# `hookz:` directive block must be rendered rather than removed. Stripping here
# would produce coverage against a file nobody has open.
#
# The consequence is a divergence worth naming: a coverage report and an
# on-chain rollback code index different files. `annotations.line_map` converts
# between them; nothing else should be guessing.
#
# Declared rather than left implicit because these paths reach clang by other
# routes (compile_hook_two_stage for DWARF, compile_hook_dev for directives),
# so a transform added to the default pipeline silently would not apply to
# them — and whether it should is a decision, not an oversight.
ANALYSIS_PIPELINE = BuildPipeline(
    name="analysis",
    summary="coverage and WCE — keeps annotations so line numbers match the "
            "source being read",
    provenance="hookz",
    compile=CompileSpec(opt_level="-O2", debug=True),
    opt=NONE,
    clean=False,
    transforms=(),
)

DEBUG_PIPELINE = BuildPipeline(
    name="debug",
    summary="unoptimised, unstripped, uncleaned — for reading, not deploying",
    provenance="hookz",
    compile=CompileSpec(opt_level="-O0", debug=True),
    opt=NONE,
    clean=False,
)

BUILD_PIPELINES: dict[str, BuildPipeline] = {
    p.name: p
    for p in (LOCAL_STRUCTURAL_PIPELINE, ANALYSIS_PIPELINE, DEBUG_PIPELINE)
}

DEFAULT_PIPELINE = LOCAL_STRUCTURAL_PIPELINE

# Rejected, not resolved. `buildbox` used to alias local-structural, so one
# command carried two spellings of the same word and only `--buildbox` called
# the service — the other quietly built here and exited 0. Every place that
# *described* the alias said so, but none of them is on the path of someone who
# types it and reads the exit code. A name that means its opposite is worse
# than an unknown name, so the wrong spelling exits pointing at both right ones.
PIPELINE_MISNOMERS = {
    "buildbox": (
        "--pipeline buildbox is not the buildbox service — it builds locally. "
        "Use --buildbox to compile through the service, or "
        "--pipeline local-structural for the local approximation of it."
    ),
}


def _misnomer(name: str) -> str | None:
    """The pointer for `name`, however the caller spelled it.

    Matched loosely on purpose. The sibling flag is `--buildbox`/`--build-box`
    and `--compiler` takes its choices case-insensitively, so this CLI has
    taught people at least four spellings of the word. An exact-match table
    would hand the pointer to `buildbox` and drop `BuildBox` and `build-box`
    into the generic "unknown pipeline" message — which is honest but tells
    the reader nothing about why the name they had every reason to expect is
    not there.
    """
    key = name.lower().replace("-", "").replace("_", "")
    for misnomer, message in PIPELINE_MISNOMERS.items():
        if key == misnomer.lower().replace("-", "").replace("_", ""):
            return message
    return None


def get_pipeline(name: str) -> BuildPipeline:
    refusal = _misnomer(name)
    if refusal is not None:
        raise ValueError(refusal)
    try:
        return BUILD_PIPELINES[name]
    except KeyError:
        known = ", ".join(sorted(BUILD_PIPELINES))
        raise ValueError(
            f"unknown build pipeline {name!r} (known: {known})") from None


# ---------------------------------------------------------------------------
# Running one, and recording what it did
# ---------------------------------------------------------------------------

@dataclass
class StageMetrics:
    """What the wasm looked like after one stage."""

    name: str
    detail: str
    size: int
    depth: int | None = None
    hook_wce: int | None = None
    cbak_wce: int | None = None
    # Why depth/WCE are absent, when they are. An un-cleaned module often
    # cannot be analysed yet; that is information, not an error.
    note: str = ""


@dataclass
class BuildTrace:
    """The artifact, plus the story of how each stage changed it."""

    pipeline: BuildPipeline
    source_path: Path
    wasm: bytes
    stages: list[StageMetrics] = field(default_factory=list)

    @property
    def final(self) -> StageMetrics:
        return self.stages[-1]

    def format_table(self) -> str:
        """One line per stage — the view that makes a regression obvious."""
        rows = [("stage", "detail", "bytes", "depth", "hook WCE")]
        for s in self.stages:
            rows.append((
                s.name,
                s.detail,
                f"{s.size:,}",
                "—" if s.depth is None else str(s.depth),
                "—" if s.hook_wce is None else f"{s.hook_wce:,}",
            ))
        widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
        out = []
        for n, row in enumerate(rows):
            out.append("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
            if n == 0:
                out.append("  ".join("-" * w for w in widths))
        return "\n".join(out)


def _resolve_transform(ref: str):
    """Import a "module:function" source transform.

    Kept deliberately dumb — no registry, no plugin discovery. A pipeline names
    an import path, and anything importable can be one.
    """
    from importlib import import_module

    module_name, _, func_name = ref.partition(":")
    if not module_name or not func_name:
        raise ValueError(
            f"transform {ref!r} must be written 'module:function'")
    try:
        module = import_module(module_name)
    except ImportError as e:
        raise ValueError(f"transform {ref!r}: cannot import {module_name!r} ({e})") from e
    fn = getattr(module, func_name, None)
    if not callable(fn):
        raise ValueError(f"transform {ref!r}: {module_name}.{func_name} is not callable")
    return fn


def _measure(name: str, detail: str, wasm: bytes) -> StageMetrics:
    """Size always; depth and WCE when the module can be analysed."""
    from .guard import analyze_wce

    m = StageMetrics(name=name, detail=detail, size=len(wasm))
    try:
        r = analyze_wce(wasm)
    except Exception as exc:  # a mid-pipeline module need not be analysable
        m.note = f"not analysable: {type(exc).__name__}: {exc}"
        return m
    if r.errors:
        m.note = "; ".join(r.errors)
    m.depth = r.max_depth
    m.hook_wce = r.hook_wce
    m.cbak_wce = r.cbak_wce
    return m


def run_pipeline(
    source: Path,
    pipeline: BuildPipeline | str | None = None,
    config: Any = None,
    dev: bool = False,
) -> BuildTrace:
    """Build `source` through a named pipeline, recording every stage.

    Args:
        source: path to the .c hook
        pipeline: a BuildPipeline, its name, or None for the default
        config: hookz config (loaded from hookz.toml if None)
        dev: unwrap `hookz:` directives first — never deployable

    Returns:
        BuildTrace holding the final wasm and per-stage metrics.
    """
    import tempfile

    from hookz.compiler import compile_hook, compile_hook_dev
    from .clean import clean_hook

    if pipeline is None:
        pipeline = DEFAULT_PIPELINE
    elif isinstance(pipeline, str):
        pipeline = get_pipeline(pipeline)

    source = Path(source)
    spec = pipeline.compile
    compile_fn = compile_hook_dev if dev else compile_hook

    # Source transforms run first. A dev build renders `hookz:` directives into
    # real code, so stripping them here would delete the very thing it is
    # building — the two passes disagree by design and dev wins.
    run_transforms = bool(pipeline.transforms) and not dev
    transform_stage: StageMetrics | None = None

    with tempfile.TemporaryDirectory() as tmpdir:
        compile_from = source
        if run_transforms:
            text = original = source.read_text()
            for ref in pipeline.transforms:
                text = _resolve_transform(ref)(text)
            # The transformed copy lives in a temp dir, NOT beside the original,
            # so `#include "helper.h"` no longer resolves on its own. clang
            # searches the *including file's* directory, which is now tmpdir.
            # Same fix, same reason, as compile_hook_dev.
            from dataclasses import replace as _replace

            from hookz.config import load_config

            if config is None:
                config = load_config(source_file=source)
            config = _replace(
                config,
                extra_cflags=[*(config.extra_cflags or []),
                              f"-I{source.resolve().parent}"],
            )
            compile_from = Path(tmpdir) / source.name
            compile_from.write_text(text)
            before, after = original.count("\n"), text.count("\n")
            transform_stage = StageMetrics(
                name="transform",
                detail=", ".join(pipeline.transforms),
                size=len(text),
                note=f"{before:,} source lines -> {after:,}"
                     + (" (unchanged)" if before == after else
                        f", {before - after:,} removed"),
            )

        wasm = compile_fn(
            compile_from,
            None,
            config,
            debug=spec.debug,
            opt_level=spec.opt_level,
            export_all=spec.export_all,
            extra_flags=spec.extra_flags,
        )

    trace = BuildTrace(pipeline=pipeline, source_path=source, wasm=wasm)
    if transform_stage is not None:
        trace.stages.append(transform_stage)
    trace.stages.append(_measure(
        "compile",
        f"clang {spec.opt_level}" + (" --export-all" if spec.export_all else ""),
        wasm,
    ))

    if pipeline.opt.invocations:
        wasm = pipeline.opt.run(wasm)
        trace.stages.append(_measure(
            "wasm-opt", f"{pipeline.opt.name} profile", wasm))

    if pipeline.clean:
        wasm = clean_hook(wasm)
        trace.stages.append(_measure("clean", "hook-cleaner", wasm))

    trace.wasm = wasm
    return trace


# ---------------------------------------------------------------------------
# Source map VLQ decoding (standard source map v3 format)
# ---------------------------------------------------------------------------

_VLQ_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_VLQ_MAP = {c: i for i, c in enumerate(_VLQ_CHARS)}


def _decode_vlq(s: str, offset: int) -> tuple[int, int]:
    """Decode a single VLQ value. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(s):
        c = s[offset]
        offset += 1
        digit = _VLQ_MAP.get(c, 0)
        cont = digit & 32
        digit &= 31
        result |= digit << shift
        shift += 5
        if not cont:
            break
    # Sign is in the LSB
    if result & 1:
        return -(result >> 1), offset
    return result >> 1, offset


def _decode_source_map_mappings(
    mappings_str: str, sources: list[str]
) -> list[tuple[int, str, int, int]]:
    """Decode the VLQ-encoded mappings string from a source map v3."""
    result = []
    if not mappings_str:
        return result

    # State
    gen_col = 0
    src_idx = 0
    src_line = 0
    src_col = 0

    # WASM source maps use "generated line" as a proxy for byte offset
    # Each semicolon advances the "generated line" (byte offset group)
    gen_line = 0

    for group in mappings_str.split(";"):
        gen_col = 0
        if not group:
            gen_line += 1
            continue

        for segment in group.split(","):
            if not segment:
                continue
            pos = 0
            # Field 1: generated column delta
            delta, pos = _decode_vlq(segment, pos)
            gen_col += delta

            if pos < len(segment):
                # Field 2: source index delta
                delta, pos = _decode_vlq(segment, pos)
                src_idx += delta

                # Field 3: source line delta
                delta, pos = _decode_vlq(segment, pos)
                src_line += delta

                # Field 4: source column delta
                delta, pos = _decode_vlq(segment, pos)
                src_col += delta

                file = sources[src_idx] if src_idx < len(sources) else ""
                result.append((gen_col, file, src_line + 1, src_col))

        gen_line += 1

    return result
