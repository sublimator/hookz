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
import re
from functools import lru_cache
from pathlib import Path

# XRPL_FEATURE(Name, Supported::yes, VoteBehavior::DefaultYes)
# XRPL_FIX    (Name, ...)   <- note the alignment padding before the paren,
# which a regex demanding `\(` immediately after the name silently skips. That
# dropped every fix from the index and left the fallback rule to cover for it —
# invisible, because the fallback produces the right answer for fixes.
_MACRO = re.compile(r"^XRPL_(FEATURE|FIX)\s*\(\s*([A-Za-z0-9_]+)", re.M)

DEFAULT_NETWORK = "mainnet"


def _data_dir() -> Path:
    return Path(__file__).parent / "data"


@lru_cache(maxsize=1)
def symbol_index() -> dict[str, str]:
    """Network-reported name -> the symbol hookz and xahaud use for it.

    Built from `features.macro`, so it is the same mapping the node makes
    rather than a restatement of it.
    """
    from hookz.wasm.xahaud_ref import vendored_root

    macro = vendored_root() / "include/xrpl/protocol/detail/features.macro"
    if not macro.exists():
        return {}
    out: dict[str, str] = {}
    for kind, name in _MACRO.findall(macro.read_text(errors="replace")):
        if kind == "FIX":
            out[f"fix{name}"] = f"fix{name}"
        else:
            out[name] = f"feature{name}"
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
    """Amendments enabled on `network`, named as hookz names them."""
    return {to_symbol(n) for n in manifest(network).get("enabled", ())}


def provenance(network: str = DEFAULT_NETWORK) -> str:
    """One line saying when and from where this was true."""
    m = manifest(network)
    if not m:
        return f"no manifest vendored for {network}"
    return (f"{network} (network {m.get('network_id')}) at ledger "
            f"{m.get('ledger_seq')}, read {m.get('queried_at')}")
