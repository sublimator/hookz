"""Ledger object helpers — keylet computation + JSON→binary for test setup.

Compute keylets the same way xahaud does (SHA-512 half of namespace + fields),
and serialize ledger entries via xrpl-py encode(). Tests use these to populate
rt.ledger so hooks can look up objects via util_keylet + slot_set.

Usage:
    from hookz.ledger import account_root_keylet, account_root

    # Just the keylet
    kl = account_root_keylet("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")

    # Keylet + serialized object
    kl, data = account_root("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", Balance="50000000")

    # In tests
    rt.ledger[kl] = data
"""

from __future__ import annotations

import hashlib
from typing import Any

from hookz.account import to_accid
from hookz.xrpl.xrpl_patch import patch_xahau_definitions

patch_xahau_definitions()

from xrpl.core.binarycodec import encode


# ---------------------------------------------------------------------------
# Keylet computation — matches xahaud Indexes.cpp
# ---------------------------------------------------------------------------

# LedgerNameSpace values (from Indexes.cpp)
_NS_ACCOUNT = 0x0061       # 'a'
_NS_TRUST_LINE = 0x0072    # 'r'
_NS_OFFER = 0x006F         # 'o'
_NS_OWNER_DIR = 0x004F     # 'O'
_NS_HOOK_STATE = 0x0076    # 'v'

# LedgerEntryType prefix (first 2 bytes of keylet)
_LT_ACCOUNT_ROOT = 0x0061  # 97
_LT_RIPPLE_STATE = 0x0072  # 114


def _sha512_half(*parts: bytes) -> bytes:
    """SHA-512 half: first 32 bytes of SHA-512 over concatenated parts."""
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()[:32]


def _index_hash(namespace: int, *args: bytes) -> bytes:
    """Compute keylet index hash: SHA-512-half(namespace_u16 + args)."""
    ns_bytes = namespace.to_bytes(2, "big")
    return _sha512_half(ns_bytes, *args)


def _make_keylet(lt_type: int, index: bytes) -> bytes:
    """Build 34-byte keylet: 2-byte type prefix + 32-byte index."""
    return lt_type.to_bytes(2, "big") + index


def _accid_bytes(account: str | bytes) -> bytes:
    """Convert account to 20-byte ID."""
    if isinstance(account, str):
        return to_accid(account)
    if len(account) != 20:
        raise ValueError(f"Account ID must be 20 bytes, got {len(account)}")
    return account


# ---------------------------------------------------------------------------
# Public keylet functions
# ---------------------------------------------------------------------------

def account_root_keylet(account: str | bytes) -> bytes:
    """Compute the 34-byte AccountRoot keylet for an account.

    Matches: keylet::account(id) → {ltACCOUNT_ROOT, indexHash(ACCOUNT, id)}
    """
    accid = _accid_bytes(account)
    return _make_keylet(_LT_ACCOUNT_ROOT, _index_hash(_NS_ACCOUNT, accid))


def trust_line_keylet(account1: str | bytes, account2: str | bytes, currency: str | bytes) -> bytes:
    """Compute the 34-byte RippleState keylet for a trust line.

    Accounts are sorted canonically (smallest first).
    Currency can be a 3-char code ("USD") or 20-byte currency ID.

    Matches: keylet::line(id0, id1, currency) →
             {ltRIPPLE_STATE, indexHash(TRUST_LINE, min(id0,id1), max(id0,id1), currency)}
    """
    acc1 = _accid_bytes(account1)
    acc2 = _accid_bytes(account2)

    # Canonical ordering — same as C++ std::minmax
    lo, hi = (acc1, acc2) if acc1 < acc2 else (acc2, acc1)

    # Currency: 3-char → pad to 20 bytes, or use raw 20 bytes
    if isinstance(currency, str):
        cur = bytearray(20)
        cur[12:12 + len(currency)] = currency.encode("ascii")
        currency_bytes = bytes(cur)
    elif len(currency) == 20:
        currency_bytes = currency
    else:
        raise ValueError(f"Currency must be 3-char string or 20 bytes, got {len(currency)}")

    return _make_keylet(_LT_RIPPLE_STATE, _index_hash(_NS_TRUST_LINE, lo, hi, currency_bytes))


# ---------------------------------------------------------------------------
# Object builders — JSON → (keylet, serialized_bytes)
# ---------------------------------------------------------------------------

def account_root(account: str, **fields: Any) -> tuple[bytes, bytes]:
    """Build an AccountRoot ledger entry.

    Returns (keylet, serialized_bytes). Pass any additional fields as kwargs.

    Example:
        kl, data = account_root("rHb9...", Balance="50000000", Sequence=5)
        rt.ledger[kl] = data
    """
    obj: dict[str, Any] = {
        "LedgerEntryType": "AccountRoot",
        "Account": account,
        "Balance": fields.pop("Balance", "0"),
        "Sequence": fields.pop("Sequence", 1),
        "Flags": fields.pop("Flags", 0),
        **fields,
    }
    kl = account_root_keylet(account)
    return kl, bytes.fromhex(encode(obj))


def ripple_state(
    account1: str,
    account2: str,
    currency: str,
    balance: str = "0",
    limit: str = "0",
    limit_peer: str = "0",
    **fields: Any,
) -> tuple[bytes, bytes]:
    """Build a RippleState (trust line) ledger entry.

    Returns (keylet, serialized_bytes).

    The Balance is from the perspective of the low account. Positive means
    the low account holds the balance, negative means the high account does.

    Example:
        kl, data = ripple_state("rAlice...", "rBob...", "USD",
                                balance="100", limit="1000")
        rt.ledger[kl] = data
    """
    lo, hi = sorted([account1, account2])
    obj: dict[str, Any] = {
        "LedgerEntryType": "RippleState",
        "Balance": {"currency": currency, "value": balance, "issuer": "rrrrrrrrrrrrrrrrrrrrrhoLvTp"},
        "LowLimit": {"currency": currency, "value": limit, "issuer": lo},
        "HighLimit": {"currency": currency, "value": limit_peer, "issuer": hi},
        "Flags": fields.pop("Flags", 0),
        **fields,
    }
    kl = trust_line_keylet(account1, account2, currency)
    return kl, bytes.fromhex(encode(obj))
