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
import struct
from typing import Any

from hookz.account import to_accid
from hookz.xrpl.xrpl_patch import patch_xahau_definitions

patch_xahau_definitions()

from xrpl.core.binarycodec import encode


# ---------------------------------------------------------------------------
# LedgerNameSpace — from xahaud src/libxrpl/protocol/Indexes.cpp
# ---------------------------------------------------------------------------

class NS:
    """LedgerNameSpace values (uint16_t, used as SHA-512 prefix)."""
    ACCOUNT = 0x0061            # 'a'
    DIR_NODE = 0x0064           # 'd'
    TRUST_LINE = 0x0072         # 'r'
    OFFER = 0x006F              # 'o'
    OWNER_DIR = 0x004F          # 'O'
    BOOK_DIR = 0x0042           # 'B'
    SKIP_LIST = 0x0073          # 's'
    ESCROW = 0x0075             # 'u'
    AMENDMENTS = 0x0066         # 'f'
    FEE_SETTINGS = 0x0065       # 'e'
    TICKET = 0x0054             # 'T'
    SIGNER_LIST = 0x0053        # 'S'
    PAYMENT_CHANNEL = 0x0078    # 'x'
    CHECK = 0x0043              # 'C'
    DEPOSIT_PREAUTH = 0x0070    # 'p'
    NEGATIVE_UNL = 0x004E       # 'N'
    HOOK = 0x0048               # 'H'
    HOOK_STATE_DIR = 0x004A     # 'J'
    HOOK_STATE = 0x0076         # 'v'
    HOOK_DEFINITION = 0x0044    # 'D'
    EMITTED_TXN = 0x0045        # 'E'
    EMITTED_DIR = 0x0046        # 'F'
    NFTOKEN_OFFER = 0x0071      # 'q'
    NFTOKEN_BUY_OFFERS = 0x0068 # 'h'
    NFTOKEN_SELL_OFFERS = 0x0069 # 'i'
    URI_TOKEN = 0x0055          # 'U'


# LedgerEntryType prefix (first 2 bytes of keylet)
class LT:
    """Ledger entry type codes (used as keylet prefix)."""
    ACCOUNT_ROOT = 0x0061
    DIR_NODE = 0x0064
    RIPPLE_STATE = 0x0072
    OFFER = 0x006F
    LEDGER_HASHES = 0x0068
    AMENDMENTS = 0x0066
    FEE_SETTINGS = 0x0073
    ESCROW = 0x0075
    SIGNER_LIST = 0x0053
    TICKET = 0x0054
    PAYCHAN = 0x0078
    CHECK = 0x0043
    DEPOSIT_PREAUTH = 0x0070
    NEGATIVE_UNL = 0x004E
    NFTOKEN_OFFER = 0x0037
    HOOK = 0x0048
    HOOK_DEFINITION = 0x0044
    HOOK_STATE = 0x0076
    EMITTED_TXN = 0x0045
    ANY = 0xFFFF  # ltANY for unchecked
    CHILD = 0xFFFF  # ltCHILD


# ---------------------------------------------------------------------------
# Core hashing
# ---------------------------------------------------------------------------

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


def _currency_bytes(currency: str | bytes) -> bytes:
    """Convert currency to 20-byte representation."""
    if isinstance(currency, str):
        cur = bytearray(20)
        cur[12:12 + len(currency)] = currency.encode("ascii")
        return bytes(cur)
    if len(currency) == 20:
        return currency
    raise ValueError(f"Currency must be 3-char string or 20 bytes, got {len(currency)}")


def _uint32_bytes(val: int) -> bytes:
    return struct.pack(">I", val)


# ---------------------------------------------------------------------------
# Keylet functions — all matching xahaud Indexes.cpp keylet::* functions
# ---------------------------------------------------------------------------

# --- Account-based (20-byte accid) ---

def account_root_keylet(account: str | bytes) -> bytes:
    """keylet::account(id) → {ltACCOUNT_ROOT, indexHash(ACCOUNT, id)}"""
    return _make_keylet(LT.ACCOUNT_ROOT, _index_hash(NS.ACCOUNT, _accid_bytes(account)))


def owner_dir_keylet(account: str | bytes) -> bytes:
    """keylet::ownerDir(id) → {ltDIR_NODE, indexHash(OWNER_DIR, id)}"""
    return _make_keylet(LT.DIR_NODE, _index_hash(NS.OWNER_DIR, _accid_bytes(account)))


def signers_keylet(account: str | bytes) -> bytes:
    """keylet::signers(id) → {ltSIGNER_LIST, indexHash(SIGNER_LIST, id, 0)}"""
    return _make_keylet(LT.SIGNER_LIST, _index_hash(NS.SIGNER_LIST, _accid_bytes(account), _uint32_bytes(0)))


def hook_keylet(account: str | bytes) -> bytes:
    """keylet::hook(id) → {ltHOOK, indexHash(HOOK, id)}"""
    return _make_keylet(LT.HOOK, _index_hash(NS.HOOK, _accid_bytes(account)))


# --- Account + sequence ---

def offer_keylet(account: str | bytes, sequence: int) -> bytes:
    """keylet::offer(id, seq) → {ltOFFER, indexHash(OFFER, id, seq)}"""
    return _make_keylet(LT.OFFER, _index_hash(NS.OFFER, _accid_bytes(account), _uint32_bytes(sequence)))


def check_keylet(account: str | bytes, sequence: int) -> bytes:
    """keylet::check(id, seq) → {ltCHECK, indexHash(CHECK, id, seq)}"""
    return _make_keylet(LT.CHECK, _index_hash(NS.CHECK, _accid_bytes(account), _uint32_bytes(sequence)))


def escrow_keylet(account: str | bytes, sequence: int) -> bytes:
    """keylet::escrow(id, seq) → {ltESCROW, indexHash(ESCROW, id, seq)}"""
    return _make_keylet(LT.ESCROW, _index_hash(NS.ESCROW, _accid_bytes(account), _uint32_bytes(sequence)))


def ticket_keylet(account: str | bytes, sequence: int) -> bytes:
    """keylet::ticket(id, seq) → {ltTICKET, indexHash(TICKET, id, seq)}"""
    return _make_keylet(LT.TICKET, _index_hash(NS.TICKET, _accid_bytes(account), _uint32_bytes(sequence)))


def nft_offer_keylet(account: str | bytes, sequence: int) -> bytes:
    """keylet::nftoffer(id, seq) → {ltNFTOKEN_OFFER, indexHash(NFTOKEN_OFFER, id, seq)}"""
    return _make_keylet(LT.NFTOKEN_OFFER, _index_hash(NS.NFTOKEN_OFFER, _accid_bytes(account), _uint32_bytes(sequence)))


# --- Trust line (two accounts + currency) ---

def trust_line_keylet(account1: str | bytes, account2: str | bytes, currency: str | bytes) -> bytes:
    """keylet::line(id0, id1, currency) — accounts sorted canonically."""
    acc1 = _accid_bytes(account1)
    acc2 = _accid_bytes(account2)
    lo, hi = (acc1, acc2) if acc1 < acc2 else (acc2, acc1)
    return _make_keylet(LT.RIPPLE_STATE, _index_hash(NS.TRUST_LINE, lo, hi, _currency_bytes(currency)))


# --- Payment channel (src + dst + sequence) ---

def paychan_keylet(src: str | bytes, dst: str | bytes, sequence: int) -> bytes:
    """keylet::payChan(src, dst, seq)"""
    return _make_keylet(LT.PAYCHAN, _index_hash(NS.PAYMENT_CHANNEL, _accid_bytes(src), _accid_bytes(dst), _uint32_bytes(sequence)))


# --- Two accounts ---

def deposit_preauth_keylet(owner: str | bytes, authorized: str | bytes) -> bytes:
    """keylet::depositPreauth(owner, authorized)"""
    return _make_keylet(LT.DEPOSIT_PREAUTH, _index_hash(NS.DEPOSIT_PREAUTH, _accid_bytes(owner), _accid_bytes(authorized)))


# --- 32-byte hash based ---

def hook_definition_keylet(hook_hash: bytes) -> bytes:
    """keylet::hookDefinition(hash) → {ltHOOK_DEFINITION, indexHash(HOOK_DEFINITION, hash)}"""
    return _make_keylet(LT.HOOK_DEFINITION, _index_hash(NS.HOOK_DEFINITION, hook_hash))


def emitted_txn_keylet(txn_id: bytes) -> bytes:
    """keylet::emittedTxn(id) → {ltEMITTED_TXN, indexHash(EMITTED_TXN, id)}"""
    return _make_keylet(LT.EMITTED_TXN, _index_hash(NS.EMITTED_TXN, txn_id))


def child_keylet(key: bytes) -> bytes:
    """keylet::child(key) → {ltCHILD, key} (identity — no hashing)"""
    return _make_keylet(LT.CHILD, key)


def unchecked_keylet(key: bytes) -> bytes:
    """keylet::unchecked(key) → {ltANY, key} (identity — no hashing)"""
    return _make_keylet(LT.ANY, key)


# --- Hook state ---

def hook_state_keylet(account: str | bytes, key: bytes, namespace: bytes) -> bytes:
    """keylet::hookState(id, key, ns) → {ltHOOK_STATE, indexHash(HOOK_STATE, id, key, ns)}"""
    return _make_keylet(LT.HOOK_STATE, _index_hash(NS.HOOK_STATE, _accid_bytes(account), key, namespace))


def hook_state_dir_keylet(account: str | bytes, namespace: bytes) -> bytes:
    """keylet::hookStateDir(id, ns) → {ltDIR_NODE, indexHash(HOOK_STATE_DIR, id, ns)}"""
    return _make_keylet(LT.DIR_NODE, _index_hash(NS.HOOK_STATE_DIR, _accid_bytes(account), namespace))


# --- Global singletons ---

def skip_keylet() -> bytes:
    """keylet::skip() → {ltLEDGER_HASHES, indexHash(SKIP_LIST)}"""
    return _make_keylet(LT.LEDGER_HASHES, _index_hash(NS.SKIP_LIST))


def amendments_keylet() -> bytes:
    """keylet::amendments() → {ltAMENDMENTS, indexHash(AMENDMENTS)}"""
    return _make_keylet(LT.AMENDMENTS, _index_hash(NS.AMENDMENTS))


def fees_keylet() -> bytes:
    """keylet::fees() → {ltFEE_SETTINGS, indexHash(FEE_SETTINGS)}"""
    return _make_keylet(LT.FEE_SETTINGS, _index_hash(NS.FEE_SETTINGS))


def negative_unl_keylet() -> bytes:
    """keylet::negativeUNL() → {ltNEGATIVE_UNL, indexHash(NEGATIVE_UNL)}"""
    return _make_keylet(LT.NEGATIVE_UNL, _index_hash(NS.NEGATIVE_UNL))


# --- NFT directories ---

def nft_buys_keylet(nft_id: bytes) -> bytes:
    """keylet::nft_buys(id) → {ltDIR_NODE, indexHash(NFTOKEN_BUY_OFFERS, id)}"""
    return _make_keylet(LT.DIR_NODE, _index_hash(NS.NFTOKEN_BUY_OFFERS, nft_id))


def nft_sells_keylet(nft_id: bytes) -> bytes:
    """keylet::nft_sells(id) → {ltDIR_NODE, indexHash(NFTOKEN_SELL_OFFERS, id)}"""
    return _make_keylet(LT.DIR_NODE, _index_hash(NS.NFTOKEN_SELL_OFFERS, nft_id))


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
