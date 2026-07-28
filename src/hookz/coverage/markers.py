"""Parse coverage markers from C source and map them to source regions.

Two spellings, because they answer different questions.

**`//@name`** — a trailing comment naming one statement. Tree-sitter decides
which AST node it is attached to, so the region is that node:

    for (int i = 0; GUARD(16), ...; ++i) //@gc_loop
    {
        state_set(0, 0, key, key_len); //@gc_delete
    }

    assert rt.coverage.region("gc_loop").entered
    assert rt.coverage.marker("gc_delete").hit

**`//@@start name` … `//@@end name`** — a span the author drew, which is what
you want when the interesting unit is a whole command block rather than one
statement. The pair names its own bounds, so the region is exactly what was
bracketed and does not depend on the AST agreeing:

    //@@start refund-path
    if (is_refund) { ... }
    //@@end refund-path

    assert rt.coverage.region("refund-path").entered

Pairs match by name, so blocks may nest. Both kinds appear in `region()`, and
`regions()` reports every one — which turns a flat list of uncovered line
numbers into "which of these blocks has nobody exercised".
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

BLOCK_START = "//@@start"
BLOCK_END = "//@@end"


def _comments(tree):
    """Every comment token in the file, innermost order irrelevant.

    Markers are read from these rather than from lines of text. tree-sitter has
    already decided what is a comment, so `//@@start` written inside a string
    literal, or sitting in the body of a `/* … */`, is not one — and a line
    scan cannot tell the difference. That is the same mistake as matching C
    syntax with a pattern, one level down.
    """
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            yield node
        stack.extend(node.children)


def _labelled(node, keyword: str) -> str | None:
    """`//@@start cmd-add` -> "cmd-add", for a comment node that is one."""
    text = node.text.decode(errors="replace").strip()
    if not text.startswith(keyword):
        return None
    rest = text[len(keyword):].strip()
    # exactly one label, so `//@@start a b` is not silently read as `a`
    return rest if rest and len(rest.split()) == 1 else None


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


def parse_block_markers(source_path: str | Path) -> list[MarkerInfo]:
    """`//@@start name` … `//@@end name` spans, paired by name so they nest.

    The region is exactly what the author bracketed. An unclosed start, or an
    end with no start, is dropped: a half-open span would silently run to the
    end of the file and report every line after it as part of the block.
    """
    source_bytes = Path(source_path).read_bytes()
    tree = Parser(C_LANGUAGE).parse(source_bytes)

    open_at: dict[str, int] = {}
    out: list[MarkerInfo] = []
    for node in sorted(_comments(tree), key=lambda n: n.start_point[0]):
        line = node.start_point[0] + 1
        name = _labelled(node, BLOCK_START)
        if name is not None:
            open_at[name] = line
            continue
        name = _labelled(node, BLOCK_END)
        if name is not None and name in open_at:
            start = open_at.pop(name)
            out.append(MarkerInfo(
                name=name,
                line=start,
                region_start=start,
                region_end=line,
                node_type="block",
                context=f"{BLOCK_START} {name}",
            ))
    return out


def parse_markers(source_path: str | Path) -> list[MarkerInfo]:
    """Every coverage marker in a C source file, both spellings.

    Returns a list of MarkerInfo with source regions.
    """
    source_path = Path(source_path)
    source_bytes = source_path.read_bytes()

    blocks = parse_block_markers(source_path)

    # //@name markers, read from comment tokens for the same reason
    raw_markers: list[tuple[int, str]] = []  # (line_no, name)
    for node in _comments(Parser(C_LANGUAGE).parse(source_bytes)):
        m = _MARKER_RE.search(node.text.decode(errors="replace").strip())
        if m:
            raw_markers.append((node.start_point[0] + 1, m.group(1)))
    raw_markers.sort()

    if not raw_markers:
        return blocks

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

    return blocks + markers
