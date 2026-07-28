"""Hook API whitelist — parsed from xahaud hook_api.macro.

Provides the allowed import functions, and their signatures, for a given set
of amendments. Used by the guard checker to validate a hook's imports the way
xahaud does: by name *and* by type.

This is a port of `getImportWhitelist()` (Enum.h:410). The output is expected
to be byte-identical to that function's, all 76 entries — see `xahaud_ref` for
the pinned revision and how to dump the C++ side and diff it.

hook_api.macro is a list of macro invocations, not a translation unit, so it
is normalised into valid C before parsing (see `_normalise`) and then parsed
with tree-sitter rather than pattern-matched.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import tree_sitter_c as tsc
from tree_sitter import Language, Parser

C_LANGUAGE = Language(tsc.language())

MACRO_NAME = "HOOK_API_DEFINITION"

# xahaud rewrites the C type names to wasm value-type codes before including
# hook_api.macro (Enum.h:417-420). void_t is not a value type
# — it encodes "no return value", i.e. a result count of 0.
WASM_TYPE_CODE = {
    "int32_t": 0x7F,
    "uint32_t": 0x7F,
    "int64_t": 0x7E,
    "void_t": 0x00,
}

VOID = 0x00

# Coverage callback, mirroring Enum.h:433 in getImportWhitelist():
#   void __on_source_line(uint32_t line, uint32_t col)
COVERAGE_IMPORT = "__on_source_line"
COVERAGE_SIGNATURE = (VOID, 0x7F, 0x7F)

# The `_t` suffix makes tree-sitter read `(uint32_t, uint32_t)` as a cast
# rather than a parenthesised expression, so each type name is swapped for a
# plain integer first. Distinct sentinels per name keep the mapping lossless —
# int32_t and uint32_t share a wasm code but not a C spelling.
_SENTINELS = {name: str(900_000 + i) for i, name in enumerate(WASM_TYPE_CODE)}
_SENTINEL_TO_TYPE = {v: k for k, v in _SENTINELS.items()}

# Longest-first: "uint32_t" contains "int32_t" as a substring.
_SUBSTITUTIONS = sorted(_SENTINELS.items(), key=lambda kv: -len(kv[0]))


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


def _normalise(text: str) -> str:
    """Turn the macro file into a parseable translation unit.

    Three rewrites, each mirroring what the C preprocessor would do for
    xahaud's own consumer in Enum.h:
      - `uint256{}` (the "no amendment" sentinel) is C++ brace-init; make it 0
        (Enum.h:425 tests `AMENDMENT == uint256{}`)
      - type names become integers, so they cannot be read as cast expressions
      - each invocation becomes its own statement, then all of it becomes a
        function body so the invocations sit where expressions are legal
    """
    text = text.replace("uint256{}", "0")
    for name, sentinel in _SUBSTITUTIONS:
        text = text.replace(name, sentinel)
    text = text.replace(MACRO_NAME, ";" + MACRO_NAME)
    return "void _hookz_macro_tu(void) {" + text + ";}"


def _iter_macro_calls(node):
    """Yield every HOOK_API_DEFINITION call_expression under `node`."""
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.text == MACRO_NAME.encode():
            yield node
    for child in node.children:
        yield from _iter_macro_calls(child)


def _type_name(node) -> str:
    name = _SENTINEL_TO_TYPE.get(node.text.decode())
    if name is None:
        raise ValueError(f"unrecognised hook API type: {node.text.decode()!r}")
    return name


def parse_hook_api_macro(path: Path | str) -> list[HookApiFunction]:
    """Parse hook_api.macro and return all function definitions."""
    text = Path(path).read_text()
    source = _normalise(text).encode()
    tree = Parser(C_LANGUAGE).parse(source)

    results = []
    for call in _iter_macro_calls(tree.root_node):
        args = [c for c in call.child_by_field_name("arguments").children if c.is_named]
        if len(args) != 4:
            raise ValueError(
                f"{MACRO_NAME} takes 4 arguments, parsed {len(args)}: "
                f"{call.text.decode()[:80]!r}"
            )
        return_node, name_node, params_node, amendment_node = args

        # params_node is `(a, b, c)` — a parenthesised comma expression, or a
        # single parenthesised identifier when the API takes one argument.
        params = tuple(
            _type_name(n)
            for n in _iter_leaf_operands(params_node)
        )

        name = name_node.text.decode()
        amendment = amendment_node.text.decode()
        # _normalise substitutes type names everywhere, not only in type
        # position. No API or amendment is named that way today, but one that
        # embedded "int32_t" would come back silently mangled — and a mangled
        # name means a whitelist that does not match xahaud's. Fail loudly.
        _reject_mangled(name, "function name")
        _reject_mangled(amendment, "amendment")
        results.append(HookApiFunction(
            name=name,
            return_type=_type_name(return_node),
            param_types=params,
            amendment="" if amendment == "0" else amendment,
        ))

    # A macro construct tree-sitter cannot parse would drop entries silently,
    # and a whitelist short an API makes hookz reject imports xahaud allows.
    # The file's own invocation count is the check.
    expected = text.count(MACRO_NAME + "(")
    if len(results) != expected:
        raise ValueError(
            f"{path}: parsed {len(results)} definitions but the file contains "
            f"{expected} {MACRO_NAME}( invocations — the whitelist would be "
            "incomplete"
        )
    return results


def _reject_mangled(token: str, what: str) -> None:
    for sentinel, type_name in _SENTINEL_TO_TYPE.items():
        if sentinel in token:
            raise ValueError(
                f"hook API {what} {token!r} contains the type name "
                f"{type_name!r}; normalisation would corrupt it"
            )


def _iter_leaf_operands(node):
    """Flatten a parenthesised comma expression into its operand nodes.

    An empty parameter list `()` is not a legal C expression, so tree-sitter
    fills it with a zero-width MISSING identifier. Those are dropped: a hook
    API taking no arguments (etxn_burden, fee_base, ...) has no operands.
    """
    if node.type in ("parenthesized_expression", "comma_expression"):
        for child in node.children:
            if child.is_named:
                yield from _iter_leaf_operands(child)
    elif not node.is_missing and node.text:
        yield node


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
