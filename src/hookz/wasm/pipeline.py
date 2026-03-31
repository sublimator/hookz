"""Pipeline types — typed stage outputs for the hook build pipeline.

Each stage produces a specific output type. Functions have clear contracts:
they take the previous stage's output and return their own.

    compiled = compile_hook(source)         → CompileOutput
    optimized = optimize_hook(compiled)     → OptimizeOutput
    cleaned = clean_hook(optimized)         → CleanOutput
    checked = guard_check(cleaned)          → GuardCheckOutput
    analysis = analyze_wce(checked)         → WceOutput
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .guard import GuardResult, BlockInfo


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
