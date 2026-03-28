"""Transaction emission — emit, etxn_reserve, etxn_details, etxn_fee_base, etxn_nonce."""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

from hookz import hookapi

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime


def etxn_reserve(rt: HookRuntime, count: int) -> int:
    if count < 1:
        return hookapi.TOO_SMALL
    if count > 255:
        return hookapi.TOO_BIG
    if getattr(rt, '_etxn_reserved', False):
        return hookapi.ALREADY_SET
    rt._etxn_reserved = True
    rt._etxn_count = count
    return count


def etxn_details(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    """Build EmitDetails exactly as xahaud does — raw serialized bytes (116 bytes)."""
    if not getattr(rt, '_etxn_reserved', False):
        return hookapi.PREREQUISITE_NOT_MET
    if write_len < 116:
        return hookapi.TOO_SMALL
    buf = bytearray()
    buf.append(0xED)  # sfEmitDetails object start

    # sfEmitGeneration
    buf.extend(b"\x20\x2E")
    buf.extend(struct.pack(">I", 1))

    # sfEmitBurden
    buf.append(0x3D)
    buf.extend(struct.pack(">Q", 1))

    # sfEmitParentTxnID
    buf.append(0x5B)
    buf.extend(b"\xAB" * 32)

    # sfEmitNonce
    buf.append(0x5C)
    buf.extend(b"\xCD" * 32)

    # sfEmitHookHash
    buf.append(0x5D)
    buf.extend(b"\x00" * 32)

    # end object
    buf.append(0xE1)

    assert len(buf) == 116
    rt._write_memory(write_ptr, bytes(buf[:write_len]))
    return len(buf)


def etxn_fee_base(rt: HookRuntime, read_ptr: int, read_len: int) -> int:
    return 10


def etxn_nonce(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    """Write a unique 32-byte nonce to WASM memory and return 32.

    Uses an incrementing counter on the runtime to produce distinct
    nonces across successive calls within a single hook execution.
    """
    if write_len < 32:
        return hookapi.TOO_SMALL

    counter = getattr(rt, "_emit_nonce_counter", 0)
    nonce = hashlib.sha512(
        b"etxn_nonce" + counter.to_bytes(8, "big")
    ).digest()[:32]
    rt._emit_nonce_counter = counter + 1

    rt._write_memory(write_ptr, nonce)
    return 32


def prepare(rt: HookRuntime, write_ptr: int, write_len: int, read_ptr: int, read_len: int) -> int:
    """Prepare a transaction for emission.

    The real C++ deserializes the blob, injects sfSequence=0,
    sfFirstLedgerSequence, sfLastLedgerSequence, sfSigningPubKey=zeros,
    sfFee, sfEmitDetails, then re-serializes.

    Test stub: copies the input bytes to the output buffer unchanged,
    returning the number of bytes written.  This lets hook code call
    prepare() without crashing while still allowing assertion on the
    raw transaction blob in tests.
    """
    if read_len == 0:
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)

    if write_len < len(data):
        return hookapi.TOO_SMALL

    rt._write_memory(write_ptr, data)
    return len(data)


def emit(rt: HookRuntime, hash_ptr: int, hash_len: int, txn_ptr: int, txn_len: int) -> int:
    if hash_len < 32:
        return hookapi.TOO_SMALL
    txn_bytes = rt._read_memory(txn_ptr, txn_len)
    rt.emitted_txns.append(txn_bytes)
    h = hashlib.sha512(txn_bytes).digest()[:32]
    rt._write_memory(hash_ptr, h[:hash_len])
    return 32
