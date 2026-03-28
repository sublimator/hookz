"""Coverage tracking with marker-based assertions.

Records line:col hits from instrumented WASM execution, then supports
assertions against //@name markers parsed from the C source.

Example:
    rt = HookRuntime()
    rt.coverage.load_source_markers("tip.c")
    result = rt.run(tip_wasm)

    assert rt.coverage.marker("gc_delete").hit
    assert rt.coverage.region("gc_loop").entered
    assert rt.coverage.branch("stale_check").true_taken
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PointCoverage:
    """Coverage for a single marker point."""
    name: str
    line: int
    hit_count: int = 0

    @property
    def hit(self) -> bool:
        return self.hit_count > 0

    @property
    def not_hit(self) -> bool:
        return self.hit_count == 0


@dataclass
class RegionCoverage:
    """Coverage for an AST region (start_line..end_line)."""
    name: str
    start_line: int
    end_line: int
    lines_hit: set[int] = field(default_factory=set)
    lines_total: set[int] = field(default_factory=set)

    @property
    def entered(self) -> bool:
        """At least one line in the region was hit."""
        return len(self.lines_hit) > 0

    @property
    def not_entered(self) -> bool:
        return len(self.lines_hit) == 0

    @property
    def completed(self) -> bool:
        """All lines with DWARF entries in the region were hit."""
        return self.lines_total and self.lines_hit >= self.lines_total

    @property
    def hit_count(self) -> int:
        return len(self.lines_hit)

    @property
    def coverage_pct(self) -> float:
        if not self.lines_total:
            return 0.0
        return 100.0 * len(self.lines_hit) / len(self.lines_total)


class CoverageTracker:
    """Track line:col coverage hits and support marker-based assertions."""

    def __init__(self) -> None:
        self._hits: dict[tuple[int, int], int] = {}  # (line, col) → count
        self._line_hits: dict[int, int] = {}  # line → count
        self._markers: list = []  # MarkerInfo objects from markers.py
        self._executable_lines: set[int] = set()  # lines with DWARF entries

    def hit(self, line: int, col: int = 0) -> None:
        """Record a hit at line:col."""
        key = (line, col)
        self._hits[key] = self._hits.get(key, 0) + 1
        self._line_hits[line] = self._line_hits.get(line, 0) + 1

    def set_executable_lines(self, locs: list, source_path: str | Path | None = None) -> None:
        """Set executable lines from DWARF SourceLoc entries.

        If source_path is given, intersects DWARF lines with tree-sitter
        AST to filter out structural syntax (lone braces, etc.).

        Args:
            locs: list of SourceLoc (from rewriter.instrument_wasm)
            source_path: optional C source path for AST-aware filtering
        """
        dwarf_lines = {loc.line for loc in locs}
        if source_path is not None:
            from hookz.coverage.markers import executable_source_lines
            ast_lines = executable_source_lines(source_path)
            self._executable_lines = dwarf_lines & ast_lines
        else:
            self._executable_lines = dwarf_lines

    @property
    def executable_lines(self) -> set[int]:
        return set(self._executable_lines)

    @property
    def uncovered_lines(self) -> set[int]:
        """Executable lines that were never hit."""
        return self._executable_lines - self.lines_hit

    def coverage_pct(self) -> float:
        """Percentage of executable lines that were hit."""
        if not self._executable_lines:
            return 0.0
        return 100.0 * len(self.lines_hit & self._executable_lines) / len(self._executable_lines)

    def load_source_markers(self, source_path: str | Path) -> None:
        """Parse //@name markers from C source file."""
        from hookz.coverage.markers import parse_markers
        self._markers = parse_markers(source_path)

    @property
    def lines_hit(self) -> set[int]:
        return {ln for ln, count in self._line_hits.items() if count > 0}

    @property
    def all_hits(self) -> dict[tuple[int, int], int]:
        return dict(self._hits)

    def line(self, line_no: int, col: int | None = None) -> PointCoverage:
        """Get coverage info for a source line."""
        if col is not None:
            count = self._hits.get((line_no, col), 0)
        else:
            count = self._line_hits.get(line_no, 0)
        return PointCoverage(name=f"line:{line_no}", line=line_no, hit_count=count)

    def marker(self, name: str) -> PointCoverage:
        """Get coverage for a //@name marker (single point)."""
        for m in self._markers:
            if m.name == name:
                count = self._line_hits.get(m.line, 0)
                return PointCoverage(name=name, line=m.line, hit_count=count)
        available = [m.name for m in self._markers]
        raise KeyError(f"Unknown marker '{name}'. Available: {available[:10]}...")

    def region(self, name: str) -> RegionCoverage:
        """Get coverage for a //@name marker's AST region.

        The region spans from the marker's AST node start to end.
        """
        for m in self._markers:
            if m.name == name:
                hit = set()
                total = set()
                for ln in range(m.region_start, m.region_end + 1):
                    if ln in self._line_hits:
                        total.add(ln)
                        if self._line_hits[ln] > 0:
                            hit.add(ln)
                    # Lines with no DWARF entry aren't in total
                    # (comments, blanks, braces)
                return RegionCoverage(
                    name=name,
                    start_line=m.region_start,
                    end_line=m.region_end,
                    lines_hit=hit,
                    lines_total=total,
                )
        available = [m.name for m in self._markers]
        raise KeyError(f"Unknown marker '{name}'. Available: {available[:10]}...")

    def render_source(self, source_path: str | Path, src_width: int = 80) -> str:
        """Render source with fixed-width columns on both sides.

        Every column is a fixed width. Source code is untouched in the center.

        Columns:
          left_name  left_bracket  line  hits │ source │ right_bracket  right_name
        """
        import re

        source_path = Path(source_path)
        source_lines = source_path.read_text().splitlines()

        # Strip //@marker comments from source display
        clean_lines = [
            re.sub(r'\s*//\s*@\w+\s*$', '', line).rstrip()
            for line in source_lines
        ]

        # Fixed column widths
        name_w = max((len(m.name) for m in self._markers), default=0) + 1  # +1 for @
        name_w = max(name_w, 2)
        num_lines = len(source_lines)
        ln_w = len(str(num_lines))
        src_w = max((len(l) for l in clean_lines), default=40)
        src_w = min(src_w, src_width)

        # Build bracket data: assign each region a depth column
        regions = sorted(
            [m for m in self._markers if m.region_end > m.region_start],
            key=lambda m: -(m.region_end - m.region_start),
        )
        points = [m for m in self._markers if m.region_end == m.region_start]
        max_depth = len(regions)
        bracket_w = max_depth + 1  # one char per nesting level

        # Per-line bracket array: bracket_w chars, one per depth slot
        # Also track which name to show on left/right
        line_brackets: dict[int, list[str]] = {}  # line → [char per depth]
        line_left_name: dict[int, str] = {}
        line_right_name: dict[int, str] = {}

        for depth, m in enumerate(regions):
            for ln in range(m.region_start, m.region_end + 1):
                if ln not in line_brackets:
                    line_brackets[ln] = [" "] * max_depth
                if ln == m.region_start:
                    line_brackets[ln][depth] = "┌"
                    line_left_name[ln] = f"@{m.name}"
                    line_right_name[ln] = f"@{m.name}"
                elif ln == m.region_end:
                    line_brackets[ln][depth] = "└"
                else:
                    line_brackets[ln][depth] = "│"

        for m in points:
            if m.line not in line_brackets:
                line_brackets[m.line] = [" "] * max_depth
            line_left_name[m.line] = f"@{m.name}"
            line_right_name[m.line] = f"@{m.name}"

        # Separate regions (multi-line, left side) from points (single-line, right side)
        region_names: dict[int, str] = {}  # line → @name (only on region start)
        point_names: dict[int, str] = {}   # line → @name (single-line markers)

        for m in regions:
            region_names[m.region_start] = f"@{m.name}"
        for m in points:
            point_names[m.line] = f"@{m.name}"

        # Column widths
        region_name_w = max((len(n) for n in region_names.values()), default=0)
        region_name_w = max(region_name_w, 2)
        point_name_w = max((len(n) for n in point_names.values()), default=0)
        point_name_w = max(point_name_w, 2)

        # Render
        out: list[str] = []
        for line_no in range(1, num_lines + 1):
            count = self._line_hits.get(line_no, 0)
            hits = f"{count:>3}x" if count > 0 else "    "
            src = clean_lines[line_no - 1] if line_no <= len(clean_lines) else ""

            brackets = line_brackets.get(line_no, [" "] * max_depth)
            bracket_str = "".join(brackets) if max_depth > 0 else ""

            # Left: region name (only on ┌ lines)
            l_name = region_names.get(line_no, "")

            # Right: point name + repeated line number
            r_name = point_names.get(line_no, "")
            if r_name:
                right = f" {line_no:>{ln_w}}  {r_name}"
            else:
                right = ""

            out.append(
                f"{l_name:>{region_name_w}} {bracket_str} "
                f"{line_no:>{ln_w}} {hits} "
                f"│ {src:<{src_w}}"
                f"{right}"
            )

        return "\n".join(out)

    def render_region(self, name: str) -> str:
        """Render a specific region's coverage."""
        rc = self.region(name)
        marker = next((m for m in self._markers if m.name == name), None)
        ctx = f" [{marker.node_type}: {marker.context}]" if marker else ""

        out: list[str] = [f"Region '{name}' lines {rc.start_line}-{rc.end_line}{ctx}:"]
        # We need source lines — try to get them from markers
        # For now just show line numbers with hit status
        for ln in range(rc.start_line, rc.end_line + 1):
            count = self._line_hits.get(ln, 0)
            status = f"{count:>3}x" if count > 0 else "   -"
            in_total = "E" if ln in rc.lines_total else " "  # E = executable
            out.append(f"  {ln:>4} {status} {in_total}")
        pct = f" ({rc.coverage_pct:.0f}%)" if rc.lines_total else ""
        out.append(f"  → {len(rc.lines_hit)}/{len(rc.lines_total)} executable lines hit{pct}")
        return "\n".join(out)

    def render_markers(self) -> str:
        """Render all markers with their hit status."""
        out: list[str] = []
        for m in self._markers:
            count = self._line_hits.get(m.line, 0)
            rc = self.region(m.name)
            status = "HIT" if rc.entered else "---"
            out.append(
                f"  {status}  {m.name:25s} line {m.line:>3} "
                f"region {m.region_start}-{m.region_end:>3} "
                f"[{m.node_type}]"
            )
        return "\n".join(out)

    def uncovered_report(self, source_path: str | Path, context: int = 1) -> str:
        """Show only executable-but-unhit lines with surrounding context.

        Args:
            source_path: path to the C source file
            context: number of context lines around each uncovered line
        """
        source_path = Path(source_path)
        source_lines = source_path.read_text().splitlines()
        uncovered = sorted(self.uncovered_lines)

        if not uncovered:
            pct = self.coverage_pct()
            return f"100% coverage ({len(self._executable_lines)} executable lines all hit)"

        # Build set of lines to show (uncovered + context)
        show_lines: set[int] = set()
        for ln in uncovered:
            for offset in range(-context, context + 1):
                show_lines.add(ln + offset)

        out: list[str] = []
        hit_count = len(self.lines_hit & self._executable_lines)
        total = len(self._executable_lines)
        out.append(f"Coverage: {hit_count}/{total} executable lines ({self.coverage_pct():.0f}%)")
        out.append(f"Uncovered: {len(uncovered)} executable lines\n")

        prev_ln = 0
        for ln in sorted(show_lines):
            if ln < 1 or ln > len(source_lines):
                continue
            if ln > prev_ln + 1 and prev_ln > 0:
                out.append("    ···")
            prev_ln = ln

            src = source_lines[ln - 1]
            count = self._line_hits.get(ln, 0)
            is_exec = ln in self._executable_lines
            if ln in self.uncovered_lines:
                marker = "  MISS"
            elif count > 0:
                marker = f"  {count:>3}x"
            elif is_exec:
                marker = "  MISS"
            else:
                marker = "      "
            out.append(f"  {ln:>4}{marker}  {src}")

        return "\n".join(out)

    def summary(self, total_lines: int | None = None) -> str:
        hit = len(self.lines_hit)
        if total_lines:
            return f"{hit}/{total_lines} lines covered ({100 * hit / total_lines:.0f}%)"
        if self._executable_lines:
            return f"{hit}/{len(self._executable_lines)} executable lines covered ({self.coverage_pct():.0f}%)"
        return f"{hit} lines covered"
