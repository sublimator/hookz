"""Hook API whitelist — parsed from xahaud hook_api.macro.

Provides the allowed import functions, and their signatures, for a given set
of amendments. Used by the guard checker to validate a hook's imports the way
xahaud does: by name *and* by type.

This is a port of `getImportWhitelist()` (xahaud:include/xrpl/hook/Enum.h:427).
Its output is expected to be identical to that function's: 77 entries at the
pinned release with every amendment enabled (75 before featureRNG added `dice`
and `util_random`) — see `xahaud_ref` for the pinned revision and how to dump
the C++ side and diff it.

hook_api.macro is a list of macro invocations, not a translation unit. Each
invocation is split into its four arguments the way the C preprocessor splits
them (commas at parenthesis depth zero), and the declaration they spell,
`RETURN_TYPE NAME PARAMS_TUPLE;`, is parsed with tree-sitter. That is the
reading xahaud itself relies on: since the 2026.10 release it consumes the
tuple as a parameter list, `(RETURN_TYPE(*) PARAMS_TUPLE) nullptr`
(xahaud:include/xrpl/hook/Enum.h:438), so parameters may be written with names
(`uint32_t read_ptr`) or bare (`uint32_t`), and both parse.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())

MACRO_NAME = "HOOK_API_DEFINITION"

# xahaud maps each C type to a wasm value type by size: 8 bytes is i64 (0x7E),
# anything else i32 (0x7F) (xahaud:include/xrpl/hook/Enum.h:413). void_t is not
# a value type — it encodes "no return value", i.e. a result count of 0, and
# appears only in the coverage import the env-tests patch adds.
WASM_TYPE_CODE = {
    "int32_t": 0x7F,
    "uint32_t": 0x7F,
    "int64_t": 0x7E,
    "void_t": 0x00,
}

VOID = 0x00


class WhitelistError(ValueError):
    """The API whitelist could not be built from the configured checkout.

    A ValueError subclass so existing callers still catch it, and its own type
    so the CLI can tell "your xahaud checkout has an unparseable macro file"
    apart from every other ValueError and render it as a verdict. It reached
    users as a traceback out of `build`, `guard-check` and `wce` — three
    commands, one unguarded read — and the cause is always the checkout rather
    than the hook being checked.
    """

# Coverage callback, from the external-env-tests patch's getImportWhitelist():
#   void __on_source_line(uint32_t line, uint32_t col)
# Upstream xahaud has no such entry; only instrumented builds import it.
COVERAGE_IMPORT = "__on_source_line"
COVERAGE_SIGNATURE = (VOID, 0x7F, 0x7F)

_INVOCATION = re.compile(r"\b" + MACRO_NAME + r"\s*\(")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NO_AMENDMENT = "uint256{}"   # xahaud:include/xrpl/hook/Enum.h:436


@dataclass(frozen=True)
class HookApiFunction:
    """A single hook API function definition."""
    name: str
    return_type: str
    param_types: tuple[str, ...]
    amendment: str  # "" = always available

    @property
    def signature(self) -> tuple[int, ...]:
        """Wasm type codes as (return, *params) — xahaud's APIWhitelist layout."""
        return (
            WASM_TYPE_CODE[self.return_type],
            *(WASM_TYPE_CODE[p] for p in self.param_types),
        )

    @property
    def result_count(self) -> int:
        """Number of wasm results: void_t returns nothing, everything else one."""
        return 0 if WASM_TYPE_CODE[self.return_type] == VOID else 1


def _strip_comments(text: str) -> str:
    """Replace each comment with a space, as translation phase 3 does before
    macros are expanded. The macro file has no string or character literals, so
    a `//` or `/*` can only open a comment."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            out.append(" ")
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _iter_macro_calls(text: str):
    """Yield the argument list of every HOOK_API_DEFINITION invocation in
    comment-free `text`, split as the preprocessor splits macro arguments: at
    commas outside any parentheses."""
    for m in _INVOCATION.finditer(text):
        depth, args, current, i = 0, [], [], m.end()
        while True:
            if i >= len(text):
                raise WhitelistError(
                    f"unterminated {MACRO_NAME}( at offset {m.start()}")
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    args.append("".join(current))
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                args.append("".join(current))
                current = []
                i += 1
                continue
            current.append(ch)
            i += 1
        yield [a.strip() for a in args]


def _type_name(text: str) -> str:
    if text not in WASM_TYPE_CODE:
        raise ValueError(f"unrecognised hook API type: {text!r}")
    return text


def _parse_declaration(return_type: str, name: str, params: str):
    """`RETURN_TYPE NAME PARAMS;` as C, via tree-sitter: (return, param types)."""
    source = f"{return_type} {name}{params};"
    root = Parser(C_LANGUAGE).parse(source.encode()).root_node
    decls = [c for c in root.named_children if c.type != "comment"]
    declarator = decls[0].child_by_field_name("declarator") if len(decls) == 1 else None
    if (root.has_error or declarator is None
            or declarator.type != "function_declarator"
            or declarator.child_by_field_name("declarator").text.decode() != name):
        raise ValueError(f"{MACRO_NAME} does not spell a declaration: {source!r}")
    param_types = []
    for p in declarator.child_by_field_name("parameters").named_children:
        if p.type == "comment":
            continue
        inner = p.child_by_field_name("declarator")
        if p.type != "parameter_declaration" or (
                inner is not None and inner.type != "identifier"):
            raise ValueError(f"unsupported hook API parameter {p.text.decode()!r} in {source!r}")
        if any(c.type in ("type_qualifier", "storage_class_specifier") for c in p.children):
            raise ValueError(f"unsupported hook API parameter {p.text.decode()!r} in {source!r}")
        param_types.append(_type_name(p.child_by_field_name("type").text.decode()))
    return _type_name(decls[0].child_by_field_name("type").text.decode()), tuple(param_types)


def parse_hook_api_macro(path: Path | str) -> list[HookApiFunction]:
    """Parse hook_api.macro and return all function definitions."""
    text = _strip_comments(Path(path).read_text())

    results = []
    for args in _iter_macro_calls(text):
        if len(args) != 4:
            raise ValueError(
                f"{MACRO_NAME} takes 4 arguments, parsed {len(args)}: "
                f"{', '.join(args)[:80]!r}"
            )
        return_text, name, params, amendment = args
        if not _IDENTIFIER.fullmatch(name):
            raise ValueError(f"hook API name {name!r} is not an identifier")
        if not (params.startswith("(") and params.endswith(")")):
            raise ValueError(f"{name}: parameter tuple {params!r} is not parenthesised")
        if amendment != _NO_AMENDMENT and not _IDENTIFIER.fullmatch(amendment):
            raise ValueError(f"{name}: amendment {amendment!r} is not an identifier")
        return_type, param_types = _parse_declaration(return_text, name, params)
        results.append(HookApiFunction(
            name=name,
            return_type=return_type,
            param_types=param_types,
            amendment="" if amendment == _NO_AMENDMENT else amendment,
        ))

    # A construct the splitter cannot see would drop entries silently, and a
    # whitelist short an API makes hookz reject imports xahaud allows. The
    # file's own invocation count, taken independently of the traversal, is
    # the check.
    expected = len(_INVOCATION.findall(text))
    if len(results) != expected:
        raise WhitelistError(
            f"{path}: parsed {len(results)} definitions but the file contains "
            f"{expected} {MACRO_NAME}( invocations — the whitelist would be "
            "incomplete"
        )
    return results


def derive_amendments(functions: list[HookApiFunction]) -> set[str]:
    """Extract all unique amendment names from the function list."""
    return {f.amendment for f in functions if f.amendment}


@lru_cache(maxsize=1)
def load_from_config() -> list[HookApiFunction]:
    """Load hook API functions, preferring xahaud checkout, falling back to vendored."""
    from hookz.xahaud_files import XahaudFile, resolve
    from hookz.config import load_config
    config = load_config()
    macro_path = resolve(XahaudFile.HOOK_API_MACRO, config.xahaud_root)
    return parse_hook_api_macro(macro_path)


def get_default_amendments() -> set[str]:
    """Every amendment named in hook_api.macro.

    The amendments that *gate an import*, which is not the same question as
    which ones a network has. See `_resolve`.
    """
    return derive_amendments(load_from_config())


def _resolve(functions: list[HookApiFunction],
             amendments: set[str] | None) -> set[str]:
    """What `amendments=None` means: the network, not every amendment.

    Enabling everything `hook_api.macro` names admits imports the network
    refuses. `prepare` is gated on featureHooksUpdate2, which mainnet vetoes,
    so a macro-derived default passes a hook that SetHook would reject — the
    accepting-what-the-network-refuses error, on the import path.

    So the same manifest `HookRuntime.amendments` is built from decides this
    too, and the two cannot drift apart. With no manifest vendored there is
    nothing to consult and the macro set is the only answer available.
    """
    if amendments is not None:
        return amendments
    from hookz.amendments import enabled_on
    return set(enabled_on()) or derive_amendments(functions)


def _enabled(functions: list[HookApiFunction], amendments: set[str] | None):
    enabled = _resolve(functions, amendments)
    return [f for f in functions if not f.amendment or f.amendment in enabled]


def get_whitelist(amendments: set[str] | None = None) -> set[str]:
    """Get allowed import function names for given amendments.

    None = the amendments recorded for mainnet in `data/amendments-mainnet.json`.
    """
    return {f.name for f in _enabled(load_from_config(), amendments)}


def get_import_signatures(
    amendments: set[str] | None = None,
    coverage: bool = False,
) -> dict[str, tuple[int, ...]]:
    """Allowed imports as name -> (return, *params) wasm type codes.

    This is xahaud's APIWhitelist. Pass coverage=True to also allow
    __on_source_line, as Enum.h getImportWhitelist() does.
    """
    sigs = {f.name: f.signature for f in _enabled(load_from_config(), amendments)}
    if coverage:
        sigs[COVERAGE_IMPORT] = COVERAGE_SIGNATURE
    return sigs


def get_function_signatures() -> dict[str, HookApiFunction]:
    """Get all function signatures by name."""
    return {f.name: f for f in load_from_config()}
