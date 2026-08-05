"""Transaction emission — emit, etxn_reserve, etxn_details, etxn_fee_base, etxn_nonce."""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

from hookz import hookapi
from hookz.emission import check_emission, emitted_txn_id

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime


def etxn_reserve(rt: HookRuntime, count: int) -> int:
    if count < 1:
        return hookapi.TOO_SMALL
    if count > 255:
        return hookapi.TOO_BIG
    if rt._etxn_reserved:
        return hookapi.ALREADY_SET
    rt._etxn_reserved = True
    rt._etxn_count = count
    return count


def etxn_details(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    """Build EmitDetails exactly as xahaud does.

    116 bytes, or 138 when the emitting hook exports `cbak` — xahaud appends
    sfEmitCallback iff `hookCtx.result.hasCallback`, which is
    "true iff this hook wasm has a cbak function"
    (xahaud:src/xrpld/app/hook/applyHook.h:166,
     xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:914).

    Always writing the short form made every hook with a callback fail its own
    length check, so hooks had to be tested against a hand-written replacement
    for this function. It also produced an emit missing a field the ledger
    requires, which emission validation now catches from the other side.
    """
    if not rt._etxn_reserved:
        return hookapi.PREREQUISITE_NOT_MET
    has_callback = bool(getattr(rt, "_has_cbak", False))
    required = 138 if has_callback else 116
    if write_len < required:
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

    # sfEmitCallback — present iff this hook exports cbak
    if has_callback:
        buf.extend(b"\x8A\x14")
        buf.extend(rt.hook_account[:20])

    # end object
    buf.append(0xE1)

    assert len(buf) == required, f"{len(buf)} != {required}"
    rt._write_memory(write_ptr, bytes(buf))
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

    counter = rt._emit_nonce_counter
    if counter >= 256:
        return hookapi.TOO_MANY_NONCES

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
    if not rt._etxn_reserved:
        return hookapi.PREREQUISITE_NOT_MET
    if len(rt.emitted_txns) >= rt._etxn_count:
        return hookapi.TOO_MANY_EMITTED_TXN
    if hash_len < 32:
        return hookapi.TOO_SMALL
    txn_bytes = rt._read_memory(txn_ptr, txn_len)

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:498 applies fourteen rules
    # and a preflight before it accepts an emitted transaction. Skipping them
    # made every emit succeed here regardless of its contents — a hook whose
    # template has a wrong offset passed the suite and is refused on chain.
    if rt.validate_emissions:
        check = check_emission(
            txn_bytes,
            hook_account=rt.hook_account,
            ledger_seq=rt.ledger_seq_val,
            min_fee=None,          # the mock's fee base is not xahaud's
            has_callback=getattr(rt, "_has_cbak", None),
            expanded_signer_list="featureExpandedSignerList" in rt.amendments,
        )
        if not check.ok:
            rt.emission_rejections.append(check)
            return hookapi.EMISSION_FAILURE
        if check.undecodable:
            # accepted, but nothing was verified — say so rather than let the
            # empty rejections list imply it passed
            rt.emission_undecided.append(check)

    rt.emitted_txns.append(txn_bytes)
    h = emitted_txn_id(txn_bytes)
    rt._write_memory(hash_ptr, h[:hash_len])
    return 32
