"""Expand a `xahaud:path:line` citation to the construct it points at.

A citation names a line, and a line is often not a claim. Verifying the ones
in this repo turned up `HookAPI.cpp:2202` → `}`, `HookAPI.cpp:511` → `try`,
and `applyHook.cpp:1905` → an empty line. Each was cited for a real reason;
none of them says anything on its own, and `check_citations` cannot tell,
because it checks that a line *exists* rather than what it contains.

Reading a fixed window either side is the usual dodge and it is worse than it
looks: too few lines and the claim is still off-screen, too many and the
citation stops being a citation. The unit a reader wants is the **construct** —
the function, the `if`, the `throw`, the declaration — so that is what this
returns, using tree-sitter rather than a heuristic about braces.

Two things fall out of having real spans:

* **A blank or punctuation line resolves upward.** `}` belongs to whatever it
  closes, so the citation lands on that.
* **Citations that share a construct merge.** Fourteen emission rules cited
  into one function collapse to one block that names all fourteen, instead of
  fourteen overlapping excerpts of the same code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Constructs worth resolving to. A compound_statement is deliberately absent:
# a bare block is where the brace lives, not what it means, so a citation
# inside one keeps walking out to the thing that owns it.
INTERESTING = frozenset({
    "function_definition", "template_declaration",
    "class_specifier", "struct_specifier", "enum_specifier",
    "namespace_definition",
    "if_statement", "else_clause", "for_statement", "while_statement",
    "do_statement", "switch_statement", "case_statement",
    "try_statement", "catch_clause",
    "declaration", "field_declaration", "expression_statement",
    "return_statement", "throw_statement",
    "preproc_def", "preproc_function_def", "preproc_ifdef",
})

# Anything this big is a container, not a claim — keep walking inward first,
# and if the only fit is larger, render it abridged.
_VERBOSE = 40


@dataclass
class Span:
    """A construct, and the cited lines that landed inside it."""
    path: str
    start: int              # 1-based, inclusive
    end: int                # 1-based, inclusive
    node_type: str
    lines: list[int] = field(default_factory=list)
    symbol: str | None = None

    @property
    def length(self) -> int:
        return self.end - self.start + 1

    def overlaps(self, other: Span) -> bool:
        return self.path == other.path and not (
            self.end < other.start or other.end < self.start)


def _parser():
    import tree_sitter_cpp as tscpp
    from tree_sitter import Language, Parser

    return Parser(Language(tscpp.language()))


def _node_at(tree, line: int):
    """The narrowest interesting construct containing a 1-based line.

    Narrowest, because a citation into a 900-line function means the statement,
    not the function. But a line holding only a brace or nothing at all is
    inside no statement, so the walk keeps going out until something owns it —
    which is how `}` resolves to what it closes.
    """
    target = line - 1
    best = None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.start_point[0] <= target <= node.end_point[0]:
            if node.type in INTERESTING:
                size = node.end_point[0] - node.start_point[0]
                if best is None or size < (best.end_point[0] - best.start_point[0]):
                    best = node
            stack.extend(node.children)
    return best



def _declarator_name(node) -> str | None:
    """The name a function_definition declares, qualifiers included.

    tree-sitter-cpp wraps `function_declarator` inside pointer/reference
    declarators when the return type carries `*` or `&`, so the name is not
    always one child down — the same unwrapping projected-source does in
    `unwrap_to_function_declarator`.
    """
    current = node.child_by_field_name("declarator")
    while current is not None:
        if current.type == "function_declarator":
            name = current.child_by_field_name("declarator")
            return name.text.decode(errors="replace") if name else None
        if current.type in ("pointer_declarator", "reference_declarator"):
            nxt = current.child_by_field_name("declarator")
            if nxt is None:
                nxt = next((c for c in current.children
                            if c.type == "function_declarator"), None)
            current = nxt
            continue
        return None
    return None


# Macros that declare a function whose real name is one of their arguments.
# Most of the hook API is written this way, so without unwrapping them every
# citation into it is labelled with the macro instead of the function.
_NAMING_MACROS = {
    "DEFINE_HOOK_FUNCTION": 1,
    "DEFINE_HOOK_FUNCNARG": 1,
}


def _macro_named_function(node) -> str | None:
    """The function name carried in a declaring macro's arguments."""
    decl = node.child_by_field_name("declarator")
    while decl is not None and decl.type != "function_declarator":
        decl = decl.child_by_field_name("declarator")
    if decl is None:
        return None
    name = decl.child_by_field_name("declarator")
    if name is None or name.text.decode(errors="replace") not in _NAMING_MACROS:
        return None
    position = _NAMING_MACROS[name.text.decode(errors="replace")]
    params = decl.child_by_field_name("parameters")
    args = [c for c in params.children if c.is_named] if params else []
    if position >= len(args):
        return None
    return args[position].text.decode(errors="replace").strip()


def enclosing_symbol(tree, line: int) -> str | None:
    """The function a line sits in, or None outside one.

    A construct type says what the code *is*; the symbol says what it is
    *for*, which is what a reader following a citation actually wants.

    Most of the hook API is declared through `DEFINE_HOOK_FUNCTION(ret, name,
    …)`, which tree-sitter reads as a function definition whose *name is the
    macro*. Labelling every one of those `DEFINE_HOOK_FUNCTION` is worse than
    saying nothing, so the real name is taken from the argument that carries
    it.
    """
    target = line - 1
    best = None
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.start_point[0] <= target <= node.end_point[0]:
            if node.type == "function_definition":
                size = node.end_point[0] - node.start_point[0]
                if best is None or size < (best.end_point[0] - best.start_point[0]):
                    best = node
            stack.extend(node.children)
    if best is None:
        return None
    return _macro_named_function(best) or _declarator_name(best)

def span_for(path: Path | str, line: int) -> Span:
    """The construct a citation points at.

    Falls back to the line itself when the file will not parse or nothing
    encloses it — a citation that cannot be expanded is still a citation, and
    silently returning someone else's code would be worse than returning one
    line.
    """
    path = Path(path)
    source = path.read_bytes()
    tree = _parser().parse(source)
    node = _node_at(tree, line)
    symbol = enclosing_symbol(tree, line)
    if node is None:
        return Span(str(path), line, line, "line", [line], symbol)
    return Span(str(path), node.start_point[0] + 1, node.end_point[0] + 1,
                node.type, [line], symbol)


def merge(spans: list[Span]) -> list[Span]:
    """Fold overlapping constructs together, keeping every cited line.

    Citations cluster — a rule and the throw that enforces it, fourteen rules
    in one function. Rendered separately they repeat the same code with the
    marker in a different place; merged, the block is shown once and every
    line that pointed into it is named.
    """
    out: list[Span] = []
    for span in sorted(spans, key=lambda s: (s.path, s.start, s.end)):
        if out and out[-1].overlaps(span):
            prev = out[-1]
            prev.start = min(prev.start, span.start)
            prev.end = max(prev.end, span.end)
            prev.lines = sorted(set(prev.lines) | set(span.lines))
            if span.length > prev.length:
                prev.node_type = span.node_type
        else:
            out.append(Span(span.path, span.start, span.end, span.node_type,
                            list(span.lines), span.symbol))
    return out


def render(span: Span, max_lines: int = _VERBOSE) -> str:
    """The construct, with the cited lines marked.

    Abridged when it is long: the head, every cited line with a little context,
    and the tail. A citation into a large function should still fit on screen,
    and the alternative — printing the whole thing — is what makes people stop
    reading citations.
    """
    text = Path(span.path).read_text(errors="replace").splitlines()
    cited = set(span.lines)
    keep: set[int] = set()
    if span.length <= max_lines:
        keep = set(range(span.start, span.end + 1))
    else:
        keep |= set(range(span.start, span.start + 3))
        keep |= set(range(span.end - 1, span.end + 1))
        for line in cited:
            keep |= set(range(line - 2, line + 3))
        keep = {n for n in keep if span.start <= n <= span.end}

    where = f" in {span.symbol}" if span.symbol else ""
    out = [f"{Path(span.path).name}:{span.start}-{span.end}  "
           f"[{span.node_type}]{where}"]
    previous = None
    for n in sorted(keep):
        if previous is not None and n > previous + 1:
            out.append("       ⋯")
        marker = "→" if n in cited else " "
        out.append(f"  {marker} {n:>5}  {text[n - 1]}")
        previous = n
    return "\n".join(out)


def expand(citations, resolve) -> list[Span]:
    """Every citation as a construct, merged where they share one.

    `resolve` maps a citation's repo-relative path to a readable file, so the
    caller decides whether that is a vendored copy or a checkout — this module
    does not need to know which repo it is running in.
    """
    spans: list[Span] = []
    for cit in citations:
        target = resolve(cit.path)
        if target is None or not Path(target).exists():
            continue
        spans.append(span_for(target, cit.line))
    return merge(spans)
