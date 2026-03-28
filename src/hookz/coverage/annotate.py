"""Annotate C source with DWARF instrumentation markers.

Takes a hook .c file and its compiled .wasm, parses DWARF for
instrumentation points, uses tree-sitter to determine AST context,
and injects named marker comments at each boundary.

Usage:
    from hookz.annotate import annotate_source, load_markers

    # Generate annotated source
    annotated, markers = annotate_source("tip.c", "tip.wasm")

    # In tests:
    assert rt.coverage.marker("gc_loop_body").hit
    assert rt.coverage.marker("insufficient_balance").not_hit
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

from hookz.coverage.rewriter import SourceLoc, parse_dwarf_locations

C_LANGUAGE = Language(tsc.language())


@dataclass
class Marker:
    """A named instrumentation point in the source."""
    id: int
    name: str
    line: int
    col: int
    ast_context: str  # e.g. "if_body", "else_body", "for_body", "function"
    ast_label: str    # e.g. "if (to_bal == 0)", "for (i = 0; ...)"
    parent_marker: int | None = None


def _get_ast_context(node, source_bytes: bytes) -> tuple[str, str]:
    """Walk up the tree-sitter AST to find the nearest meaningful context."""
    current = node
    while current is not None:
        ntype = current.type

        if ntype == "if_statement":
            # Get the condition text
            cond = current.child_by_field_name("condition")
            cond_text = source_bytes[cond.start_byte:cond.end_byte].decode(errors="replace") if cond else "?"
            # Are we in the consequence or alternative?
            return "if", cond_text.strip()[:60]

        if ntype == "else_clause":
            # Find the parent if
            parent_if = current.parent
            if parent_if and parent_if.type == "if_statement":
                cond = parent_if.child_by_field_name("condition")
                cond_text = source_bytes[cond.start_byte:cond.end_byte].decode(errors="replace") if cond else "?"
                return "else", cond_text.strip()[:60]
            return "else", ""

        if ntype == "for_statement":
            # Get the full for(...) header
            header_end = None
            for child in current.children:
                if child.type == "compound_statement":
                    header_end = child.start_byte
                    break
            if header_end:
                header = source_bytes[current.start_byte:header_end].decode(errors="replace").strip()
            else:
                header = "for(...)"
            return "for", header[:60]

        if ntype == "while_statement":
            cond = current.child_by_field_name("condition")
            cond_text = source_bytes[cond.start_byte:cond.end_byte].decode(errors="replace") if cond else "?"
            return "while", cond_text.strip()[:60]

        if ntype == "function_definition":
            declarator = current.child_by_field_name("declarator")
            if declarator:
                name = source_bytes[declarator.start_byte:declarator.end_byte].decode(errors="replace")
                return "function", name.strip()[:60]
            return "function", "?"

        if ntype == "compound_statement":
            # Check parent for context
            pass

        if ntype == "expression_statement":
            expr = source_bytes[current.start_byte:current.end_byte].decode(errors="replace").strip()
            return "stmt", expr[:60]

        if ntype == "return_statement":
            expr = source_bytes[current.start_byte:current.end_byte].decode(errors="replace").strip()
            return "return", expr[:60]

        if ntype == "declaration":
            expr = source_bytes[current.start_byte:current.end_byte].decode(errors="replace").strip()
            return "decl", expr[:60]

        current = current.parent

    return "unknown", ""


def _find_node_at(tree, line: int, col: int):
    """Find the deepest tree-sitter node at (line, col). Line is 1-based."""
    root = tree.root_node

    def _walk(node):
        # tree-sitter uses 0-based lines
        ts_line = line - 1
        point = (ts_line, col)

        best = node
        for child in node.children:
            if child.start_point <= point <= child.end_point:
                deeper = _walk(child)
                if deeper is not None:
                    best = deeper

        if node.start_point <= point <= node.end_point:
            return best
        return None

    return _walk(root)


def analyze_markers(
    source_path: str | Path,
    wasm_path: str,
) -> list[Marker]:
    """Analyze a hook source file and return markers for each DWARF instrumentation point.

    Args:
        source_path: Path to the C source file
        wasm_path: Path to the compiled WASM (with -g)

    Returns:
        List of Marker objects, one per unique (line, col) DWARF entry
    """
    source_path = Path(source_path)
    source_bytes = source_path.read_bytes()
    source_text = source_bytes.decode(errors="replace")

    # Parse DWARF
    locs = parse_dwarf_locations(wasm_path)

    # Deduplicate by (line, col)
    seen: set[tuple[int, int]] = set()
    unique_locs: list[SourceLoc] = []
    for loc in locs:
        key = (loc.line, loc.col)
        if key not in seen:
            seen.add(key)
            unique_locs.append(loc)

    # Parse with tree-sitter
    parser = Parser(C_LANGUAGE)
    tree = parser.parse(source_bytes)

    # Build markers
    markers: list[Marker] = []
    for i, loc in enumerate(sorted(unique_locs, key=lambda l: (l.line, l.col))):
        node = _find_node_at(tree, loc.line, loc.col)
        if node:
            ctx_type, ctx_label = _get_ast_context(node, source_bytes)
        else:
            ctx_type, ctx_label = "unknown", ""

        # Auto-generate a name from context
        name = f"e{i}"
        if ctx_type in ("if", "else", "for", "while"):
            # Sanitize the label for use as an identifier
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', ctx_label)[:30].strip('_').lower()
            name = f"{ctx_type}_{safe}" if safe else f"{ctx_type}_{i}"

        markers.append(Marker(
            id=i,
            name=name,
            line=loc.line,
            col=loc.col,
            ast_context=ctx_type,
            ast_label=ctx_label,
        ))

    return markers


def annotate_source(
    source_path: str | Path,
    wasm_path: str,
    marker_file: str | Path | None = None,
) -> tuple[str, list[Marker]]:
    """Generate annotated source with marker comments at DWARF boundaries.

    Returns (annotated_source_text, markers).
    If marker_file exists, loads custom names from it.
    """
    source_path = Path(source_path)
    source_lines = source_path.read_text().splitlines()
    markers = analyze_markers(source_path, wasm_path)

    # Load custom names from marker file if it exists
    if marker_file:
        marker_path = Path(marker_file)
        if marker_path.exists():
            custom_names = _load_marker_names(marker_path)
            for m in markers:
                key = (m.line, m.col)
                if key in custom_names:
                    m.name = custom_names[key]

    # Group markers by line
    line_markers: dict[int, list[Marker]] = {}
    for m in markers:
        line_markers.setdefault(m.line, []).append(m)

    # Build annotated output
    output_lines: list[str] = []
    for line_no, line_text in enumerate(source_lines, 1):
        if line_no in line_markers:
            ms = sorted(line_markers[line_no], key=lambda m: m.col)
            tags = " ".join(f"/*@{m.name}*/" for m in ms)
            output_lines.append(f"{line_text}  {tags}")
        else:
            output_lines.append(line_text)

    return "\n".join(output_lines), markers


def save_marker_names(markers: list[Marker], path: str | Path) -> None:
    """Save marker names to a file for customization.

    Format: line:col = name  # ast_context: ast_label
    """
    path = Path(path)
    lines = ["# Hook coverage markers — edit names as desired\n"]
    for m in markers:
        lines.append(f"{m.line}:{m.col} = {m.name}  # {m.ast_context}: {m.ast_label}\n")
    path.write_text("".join(lines))


def _load_marker_names(path: Path) -> dict[tuple[int, int], str]:
    """Load custom marker names from file."""
    names: dict[tuple[int, int], str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Parse: line:col = name  # comment
        m = re.match(r"(\d+):(\d+)\s*=\s*(\S+)", line)
        if m:
            names[(int(m.group(1)), int(m.group(2)))] = m.group(3)
    return names


def load_markers(path: str | Path) -> dict[str, tuple[int, int]]:
    """Load marker name → (line, col) mapping for use in test assertions."""
    names = _load_marker_names(Path(path))
    return {name: lc for lc, name in names.items()}
