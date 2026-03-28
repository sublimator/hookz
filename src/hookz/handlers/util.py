"""Utility functions — sha512h, keylet, hook_account, ledger_seq, ledger_nonce, accid, raddr, hook_hash, ledger_last_hash."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from hookz import hookapi
from hookz.account import to_accid, to_raddr

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime


def util_sha512h(rt: HookRuntime, write_ptr: int, write_len: int, read_ptr: int, read_len: int) -> int:
    if write_len < 32:
        return hookapi.TOO_SMALL
    data = rt._read_memory(read_ptr, read_len)
    h = hashlib.sha512(data).digest()[:32]
    rt._write_memory(write_ptr, h[:write_len])
    return 32


def util_keylet(rt: HookRuntime, *args) -> int:
    write_ptr, write_len = args[0], args[1]
    rt._write_memory(write_ptr, b"\x00" * min(write_len, 34))
    return 34


def hook_account(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    if write_len < 20:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, rt.hook_account[:write_len])
    return 20


def ledger_seq(rt: HookRuntime) -> int:
    return rt.ledger_seq_val


def ledger_nonce(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    if write_len < 32:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, b"\xCD" * min(write_len, 32))
    return 32


def util_accid(rt: HookRuntime, write_ptr: int, write_len: int, read_ptr: int, read_len: int) -> int:
    """r-address string → 20-byte account ID.

    Mirrors xahaud util_accid: reads an r-address from WASM memory,
    decodes it to a 20-byte account ID, writes it to the output buffer.
    """
    if write_len < 20:
        return hookapi.TOO_SMALL
    if read_len > 49:
        return hookapi.TOO_BIG

    raddr_bytes = rt._read_memory(read_ptr, read_len)
    raddr = raddr_bytes.rstrip(b"\x00").decode("ascii")

    try:
        accid = to_accid(raddr)
    except Exception:
        return hookapi.INVALID_ARGUMENT

    rt._write_memory(write_ptr, accid)
    return 20


def util_raddr(rt: HookRuntime, write_ptr: int, write_len: int, read_ptr: int, read_len: int) -> int:
    """20-byte account ID → r-address string.

    Mirrors xahaud util_raddr: reads a 20-byte account ID from WASM memory,
    encodes it as an r-address string, writes it to the output buffer.
    Returns the length of the r-address written.
    """
    accid = rt._read_memory(read_ptr, read_len)

    try:
        raddr = to_raddr(accid)
    except Exception:
        return hookapi.INVALID_ARGUMENT

    raddr_bytes = raddr.encode("ascii")
    if write_len < len(raddr_bytes):
        return hookapi.TOO_SMALL

    rt._write_memory(write_ptr, raddr_bytes)
    return len(raddr_bytes)


def hook_hash(rt: HookRuntime, write_ptr: int, write_len: int, hook_no: int) -> int:
    """Write the 32-byte hook hash to WASM memory, return 32.

    Stub implementation: writes 32 zero bytes.
    """
    if write_len < 32:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, b"\x00" * 32)
    return 32


def hook_skip(rt: HookRuntime, hash_ptr: int, hash_len: int, flags: int) -> int:
    """Skip execution of another hook in the chain.

    Stub: returns 1 (success). In xahaud this manages a skip set
    on the hook context, but for testing we just acknowledge the call.
    """
    if hash_len != 32:
        return hookapi.INVALID_ARGUMENT
    if flags != 0 and flags != 1:
        return hookapi.INVALID_ARGUMENT
    return 1


def ledger_keylet(
    rt: HookRuntime,
    write_ptr: int, write_len: int,
    lread_ptr: int, lread_len: int,
    hread_ptr: int, hread_len: int,
) -> int:
    """Construct a keylet from two input keylets (lo/hi range).

    Stub: writes 34 zero bytes to the output buffer and returns 34.
    The real implementation searches the ledger between the two keylet bounds.
    """
    if write_len < 34 or lread_len < 34 or hread_len < 34:
        return hookapi.TOO_SMALL
    if write_len > 34 or lread_len > 34 or hread_len > 34:
        return hookapi.TOO_BIG
    rt._write_memory(write_ptr, b"\x00" * 34)
    return 34


def util_verify(
    rt: HookRuntime,
    dread_ptr: int,
    dread_len: int,
    sread_ptr: int,
    sread_len: int,
    kread_ptr: int,
    kread_len: int,
) -> int:
    """Verify a cryptographic signature against data and a public key.

    Mirrors xahaud util_verify: validates key length (33 bytes), data
    non-empty, signature >= 30 bytes, then verifies the signature.

    For testing, returns 1 (valid) by default.  Override via
    ``rt.handlers["util_verify"]`` to supply a custom callable for
    tests that need specific behaviour.
    """
    if kread_len != 33:
        return hookapi.INVALID_KEY
    if dread_len == 0:
        return hookapi.TOO_SMALL
    if sread_len < 30:
        return hookapi.TOO_SMALL

    # Allow test-level override via rt.handlers
    override = getattr(rt, "handlers", {}).get("util_verify")
    if override is not None:
        data = rt._read_memory(dread_ptr, dread_len)
        sig = rt._read_memory(sread_ptr, sread_len)
        key = rt._read_memory(kread_ptr, kread_len)
        return override(data, sig, key)

    # Default stub: signature is valid
    return 1


def ledger_last_hash(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    """Write the 32-byte hash of the last closed ledger, return 32.

    Stub implementation: writes a deterministic value (sha512-half of
    b"ledger_last_hash") so tests can assert on a known constant.
    """
    if write_len < 32:
        return hookapi.TOO_SMALL
    stub = hashlib.sha512(b"ledger_last_hash").digest()[:32]
    rt._write_memory(write_ptr, stub)
    return 32
