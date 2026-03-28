"""Parse //@name markers from C source and map to AST regions via tree-sitter.

A marker is a //@name comment at the end of a line in the C source.
Tree-sitter determines which AST node the marker is attached to,
giving us a source region (start line, end line) for coverage assertions.

Example source:
    for (int i = 0; GUARD(16), ...; ++i) //@gc_loop
    {
        state_set(0, 0, key, key_len); //@gc_delete
    }

Example test:
    assert rt.coverage.region("gc_loop").entered
    assert rt.coverage.marker("gc_delete").hit
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())

# Matches //@name at end of line (with optional whitespace)
_MARKER_RE = re.compile(r"//\s*@(\w+)\s*$")


@dataclass
class MarkerInfo:
    """A named marker and its AST-derived region."""
    name: str
    line: int           # 1-based line where the marker appears
    region_start: int   # 1-based first line of the AST node
    region_end: int     # 1-based last line of the AST node
    node_type: str      # tree-sitter node type (if_statement, for_statement, etc.)
    context: str        # short description of what the node is


def _find_statement_node(tree, line: int, source_bytes: bytes):
    """Find the most specific statement-level AST node at the given line (1-based).

    Walks the tree to find the narrowest "interesting" node whose range
    includes this line. Skips comment nodes.
    """
    ts_line = line - 1  # tree-sitter is 0-based

    INTERESTING = {
        "if_statement", "else_clause", "for_statement", "while_statement",
        "do_statement", "switch_statement", "case_statement",
        "function_definition",
        "expression_statement", "return_statement", "declaration",
        "break_statement", "continue_statement",
    }

    best = None

    def _walk(node):
        nonlocal best
        # Does this node's range include our line?
        if node.start_point[0] <= ts_line <= node.end_point[0]:
            if node.type in INTERESTING:
                # Prefer narrower (more specific) nodes
                if best is None or (node.end_point[0] - node.start_point[0]) < (best.end_point[0] - best.start_point[0]):
                    best = node
            for child in node.children:
                _walk(child)

    _walk(tree.root_node)
    return best


def _describe_node(node, source_bytes: bytes) -> str:
    """Short description of an AST node."""
    ntype = node.type

    if ntype == "if_statement":
        cond = node.child_by_field_name("condition")
        if cond:
            return f"if {source_bytes[cond.start_byte:cond.end_byte].decode(errors='replace').strip()}"
        return "if ..."

    if ntype == "else_clause":
        return "else"

    if ntype == "for_statement":
        return "for loop"

    if ntype == "while_statement":
        cond = node.child_by_field_name("condition")
        if cond:
            return f"while {source_bytes[cond.start_byte:cond.end_byte].decode(errors='replace').strip()}"
        return "while ..."

    if ntype == "function_definition":
        decl = node.child_by_field_name("declarator")
        if decl:
            return f"fn {source_bytes[decl.start_byte:decl.end_byte].decode(errors='replace').strip()}"
        return "function"

    if ntype == "return_statement":
        text = source_bytes[node.start_byte:node.end_byte].decode(errors="replace").strip()
        return text[:60]

    if ntype in ("expression_statement", "declaration"):
        text = source_bytes[node.start_byte:node.end_byte].decode(errors="replace").strip()
        return text[:60]

    return ntype


def executable_source_lines(source_path: str | Path) -> set[int]:
    """Use tree-sitter AST to find lines containing executable statements.

    Returns 1-based line numbers where executable code exists.
    Filters out structural syntax like lone `{`, `}`, declarations
    without side effects, comments, etc.
    """
    source_path = Path(source_path)
    source_bytes = source_path.read_bytes()

    parser = Parser(C_LANGUAGE)
    tree = parser.parse(source_bytes)

    EXECUTABLE_TYPES = {
        "expression_statement", "return_statement",
        "break_statement", "continue_statement", "goto_statement",
        "if_statement", "for_statement", "while_statement",
        "do_statement", "switch_statement", "case_statement",
        "declaration",  # includes initializers like int x = foo()
    }

    lines: set[int] = set()

    def _walk(node):
        if node.type in EXECUTABLE_TYPES:
            lines.add(node.start_point[0] + 1)  # 1-based
        for child in node.children:
            _walk(child)

    _walk(tree.root_node)
    return lines


def parse_markers(source_path: str | Path) -> list[MarkerInfo]:
    """Parse //@name markers from a C source file.

    Returns a list of MarkerInfo with AST-derived regions.
    """
    source_path = Path(source_path)
    source_bytes = source_path.read_bytes()
    source_lines = source_bytes.decode(errors="replace").splitlines()

    # Find all //@name markers
    raw_markers: list[tuple[int, str]] = []  # (line_no, name)
    for line_no, line_text in enumerate(source_lines, 1):
        m = _MARKER_RE.search(line_text)
        if m:
            raw_markers.append((line_no, m.group(1)))

    if not raw_markers:
        return []

    # Parse with tree-sitter — strip marker comments so they don't affect AST
    parser = Parser(C_LANGUAGE)
    clean_source = _MARKER_RE.sub("", source_bytes.decode(errors="replace"))
    clean_bytes = clean_source.encode()
    tree = parser.parse(clean_bytes)

    markers: list[MarkerInfo] = []
    for line_no, name in raw_markers:
        node = _find_statement_node(tree, line_no, clean_bytes)
        if node:
            markers.append(MarkerInfo(
                name=name,
                line=line_no,
                region_start=node.start_point[0] + 1,  # to 1-based
                region_end=node.end_point[0] + 1,
                node_type=node.type,
                context=_describe_node(node, clean_bytes),
            ))
        else:
            # Fallback: marker is a single-line point
            markers.append(MarkerInfo(
                name=name,
                line=line_no,
                region_start=line_no,
                region_end=line_no,
                node_type="unknown",
                context="",
            ))

    return markers
