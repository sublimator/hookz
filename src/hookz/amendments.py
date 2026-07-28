"""Which amendments a hook should be tested against, and why those.

An amendment changes what the network does — `fixFloatDivide` changes the
result of a division, `ExpandedSignerList` changes how many signers a list may
carry, `fixGuardDepth32` changes the nesting limit a hook must fit inside. So
the set hookz enables *is* the chain a test runs on, and a set that disagrees
with mainnet produces answers about a network nobody is using.

It used to be a hand-written list of eight. Measured against mainnet it was
wrong in both directions at once: it enabled three amendments mainnet does not
have (accepting what the network refuses) and omitted thirty-three it does
(refusing what the network accepts). Neither error is visible from inside — a
curated list looks equally plausible whichever way it is wrong.

So it is no longer curated. `data/amendments-<network>.json` is a manifest read
off a live node, carrying the ledger it was read at and when, so staleness is a
fact you can see rather than a thing you assume. Regenerate with:

    x-inspect-net amendments --net mainnet \\
        --json src/hookz/data/amendments-mainnet.json

NAMES
-----
The manifest records what the network reports, which is not what hookz calls
these. xahaud registers them as
(xahaud:src/libxrpl/protocol/Feature.cpp:427):

    XRPL_FEATURE(name, …)  ->  registerFeature(#name, …)         "Hooks"
    XRPL_FIX(name, …)      ->  registerFeature("fix" #name, …)   "fixFloatDivide"

while the C++ symbols — and hookz's convention, inherited from the hook API
macro — are `feature##name` and `fix##name`. So a fix is reported exactly as
hookz names it and a feature is reported without its prefix.

That rule is derived from the vendored `features.macro` rather than assumed,
because "starts with fix" is a guess that holds until someone names a feature
`fixSomething`, and the failure would be a silently absent amendment.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

# The invocations we care about. XRPL_RETIRE names amendments that no longer
# exist, so it is parsed and ignored rather than skipped by pattern.
_KINDS = {"XRPL_FEATURE": "feature", "XRPL_FIX": "fix"}

# C++ scope resolution is not C. Substituted rather than stripped so the
# argument still parses as one identifier.
_CPP_SCOPE = "::"

DEFAULT_NETWORK = "mainnet"


def _data_dir() -> Path:
    return Path(__file__).parent / "data"


def _normalise(text: str) -> str:
    """Turn the macro file into a parseable translation unit.

    Same approach as `wasm.whitelist._normalise`, for the same reason: this is
    a list of macro invocations, not C, so it is made into C rather than
    pattern-matched. `Supported::yes` is C++; each invocation needs a
    terminator; and the whole lot has to sit where expressions are legal.
    """
    text = text.replace(_CPP_SCOPE, "_")
    for macro in _KINDS:
        text = text.replace(macro, ";" + macro)
    return "void _hookz_features_tu(void) {" + text + ";}"


def _iter_macro_calls(node):
    """Every XRPL_FEATURE / XRPL_FIX call_expression under `node`."""
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None and fn.text.decode() in _KINDS:
            yield node
    for child in node.children:
        yield from _iter_macro_calls(child)


@lru_cache(maxsize=1)
def symbol_index() -> dict[str, str]:
    """Network-reported name -> the symbol hookz and xahaud use for it.

    Parsed from `features.macro` with tree-sitter, so it is the same mapping
    the node makes rather than a restatement of it — and so the answer does not
    depend on how the file is laid out. The first attempt here was a regex
    requiring `(` immediately after the macro name; the file writes
    `XRPL_FIX    (Name` with alignment padding, and every fix went missing.
    """
    import tree_sitter_c as tsc
    from tree_sitter import Language, Parser

    from hookz.wasm.xahaud_ref import vendored_root

    macro = vendored_root() / "include/xrpl/protocol/detail/features.macro"
    if not macro.exists():
        return {}

    source = _normalise(macro.read_text(errors="replace")).encode()
    tree = Parser(Language(tsc.language())).parse(source)

    out: dict[str, str] = {}
    for call in _iter_macro_calls(tree.root_node):
        kind = _KINDS[call.child_by_field_name("function").text.decode()]
        args = call.child_by_field_name("arguments")
        named = [c for c in args.children if c.is_named] if args else []
        if not named:
            continue
        name = named[0].text.decode()
        # a fix is registered with its prefix, a feature bare
        # (xahaud:src/libxrpl/protocol/Feature.cpp:427)
        reported = f"fix{name}" if kind == "fix" else name
        out[reported] = f"{kind}{name}"
    return out


def to_symbol(reported: str) -> str:
    """One network-reported amendment name, as hookz spells it.

    Falls back to the prefix rule for a name the vendored macro does not know —
    a node newer than the pin will report amendments hookz has never heard of,
    and dropping them silently would be worse than naming them by convention.
    """
    known = symbol_index().get(reported)
    if known is not None:
        return known
    return reported if reported.startswith("fix") else f"feature{reported}"


@lru_cache(maxsize=4)
def manifest(network: str = DEFAULT_NETWORK) -> dict:
    """The recorded amendment state of a network, or {} if not vendored."""
    path = _data_dir() / f"amendments-{network}.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    # the CLI writes {network: {...}}; accept either shape
    return data.get(network, data)


def enabled_on(network: str = DEFAULT_NETWORK) -> set[str]:
    """Amendments enabled on `network`, named as hookz names them.

    A manifest records `enabled_unstable` when the backends it sampled did not
    agree about what the ledger has. The merged answer is then whichever
    reading was more common — on an even split, whichever was seen first — and
    every hook test runs against it. That is worth one warning rather than a
    silently authoritative set.
    """
    m = manifest(network)
    unstable = m.get("enabled_unstable") or ()
    if unstable:
        import warnings
        warnings.warn(
            f"the {network} manifest records disagreement about whether "
            f"{', '.join(sorted(unstable))} {'is' if len(unstable) == 1 else 'are'} "
            "enabled, so the set hookz tests against was resolved by majority "
            f"vote across samples. Regenerate it from a consistent endpoint: "
            f"x-inspect-net amendments --net {network} --json <path>",
            RuntimeWarning, stacklevel=2)
    return {to_symbol(n) for n in m.get("enabled", ())}


def provenance(network: str = DEFAULT_NETWORK) -> str:
    """One line saying when and from where this was true."""
    m = manifest(network)
    if not m:
        return f"no manifest vendored for {network}"
    return (f"{network} (network {m.get('network_id')}) at ledger "
            f"{m.get('ledger_seq')}, read {m.get('queried_at')}")
