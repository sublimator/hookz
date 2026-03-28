"""Reusable test helpers — seed state, build opinions, make amounts."""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz.xfl import float_to_xfl, xfl_to_float


# ---- Member seeding (tip.c oracle game) ----

def seed_members(rt: HookRuntime, members: list[tuple[bytes, int]]):
    """Seed members bitfield and register each (account, seat) pair.

    Args:
        rt: HookRuntime instance
        members: list of (20-byte account, seat_number) tuples
    """
    sm_key = b"SM" + b"\x00" * 30
    bf = bytearray(32)
    for acc, seat in members:
        bf[seat >> 3] |= 1 << (seat % 8)
        m_key = b"M" + acc[:20]
        rt.state_db[m_key] = bytes([seat])
        p_key = b"\x00" * 30 + b"P" + bytes([seat])
        rt.state_db[p_key] = acc[:20]
    rt.state_db[sm_key] = bytes(bf)


# ---- Balance helpers ----

def balance_key(user_id: int = 99, snid: int = 1,
                currency: bytes | None = None, issuer: bytes | None = None) -> bytes:
    """Compute the 'B'-prefixed sha512h balance key for a social user."""
    buf = bytearray(60)
    buf[0] = snid
    struct.pack_into("<Q", buf, 12, user_id)
    if currency:
        buf[20:40] = currency[:20]
    if issuer:
        buf[40:60] = issuer[:20]
    h = hashlib.sha512(bytes(buf)).digest()[:32]
    key = bytearray(h)
    key[0] = ord('B')
    return bytes(key)


def balance_key_account(account: bytes, currency: bytes | None = None,
                        issuer: bytes | None = None) -> bytes:
    """Compute the 'B'-prefixed sha512h balance key for an account (top.c style)."""
    key_material = account[:20] + (currency or b"\x00" * 20) + (issuer or b"\x00" * 20)
    h = hashlib.sha512(key_material).digest()[:32]
    return b"B" + h[1:]


def seed_balance(rt: HookRuntime, user_id: int = 99, amount_xfl: int = 0,
                 snid: int = 1, currency: bytes | None = None,
                 issuer: bytes | None = None, bal_idx: int = 0):
    """Seed a balance entry in state for a social user (tip.c style)."""
    key = balance_key(user_id, snid, currency, issuer)
    val = bytearray(9)
    struct.pack_into("<Q", val, 0, amount_xfl)
    val[8] = bal_idx
    rt.state_db[key] = bytes(val)


def seed_xah_balance(rt: HookRuntime, account: bytes, xfl_amount: int, bal_idx: int = 0):
    """Seed an XAH balance + user info for an account (top.c style)."""
    key = balance_key_account(account)
    val = struct.pack("<Q", xfl_amount) + bytes([bal_idx])
    rt.state_db[key] = val
    ui_key = b"U" + account[:20]
    ui_val = bytearray(32)
    ui_val[bal_idx >> 3] |= 1 << (bal_idx % 8)
    rt.state_db[ui_key] = bytes(ui_val)


# ---- Opinion builders (tip.c) ----

def make_opinion(snid: int = 1, post_id: int = 1001, to_user_id: int = 42,
                 from_user_id: int = 99, amount_xfl: int = 0x5496_1540_0000_0000,
                 to_acc: bytes | None = None, currency: bytes | None = None,
                 issuer: bytes | None = None) -> bytes:
    """Build an 85-byte opinion parameter value for tip.c."""
    op = bytearray(85)
    op[0] = snid
    struct.pack_into("<Q", op, 1, post_id)
    if to_acc is not None:
        op[9:9 + len(to_acc)] = to_acc[:20]
    else:
        struct.pack_into("<Q", op, 21, to_user_id)
    struct.pack_into("<Q", op, 29, from_user_id)
    if currency:
        op[37:37 + len(currency)] = currency[:20]
    if issuer:
        op[57:57 + len(issuer)] = issuer[:20]
    struct.pack_into("<Q", op, 77, amount_xfl)
    return bytes(op)


# ---- Voting helpers (tip.c oracle game) ----

MEMBER_0 = b"\x02" + b"\x00" * 19
MEMBER_1 = b"\x03" + b"\x00" * 19
MEMBER_2 = b"\x04" + b"\x00" * 19


def action_opinion(rt: HookRuntime, hook, opinion: bytes,
                   voters: tuple[bytes, bytes] = (MEMBER_0, MEMBER_1)):
    """Drive an opinion through threshold with 2 members.

    Runs the hook twice — once per voter — to meet the 2-of-3 threshold.
    Returns the result of the second (actioning) run.
    """
    rt.otxn_account = voters[0]
    rt.set_param(0, opinion)
    rt.run(hook)
    rt.otxn_account = voters[1]
    rt.set_param(0, opinion)
    return rt.run(hook)


# ---- Amount serialization (top.c deposits) ----

def make_xah_amount(drops: int) -> bytes:
    """Build 9-byte serialized XAH amount: sfAmount header + 8 byte drops."""
    buf = bytearray(9)
    buf[0] = 0x61  # sfAmount: type=6, field=1
    struct.pack_into(">Q", buf, 1, (0x40 << 56) | drops)
    return bytes(buf)
