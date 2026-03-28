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


def util_keylet(
    rt: HookRuntime,
    write_ptr: int, write_len: int,
    keylet_type: int,
    a: int, b: int, c: int, d: int, e: int, f: int,
) -> int:
    """Compute a keylet and write 34 bytes to WASM memory.

    Matches the full xahaud util_keylet switch statement from applyHook.cpp.
    Args a-f are interpreted differently per keylet type.
    """
    if write_len < 34:
        return hookapi.TOO_SMALL

    import hookz.ledger as L

    kl = None
    kt = keylet_type

    # --- 20-byte account keylets: ACCOUNT, OWNER_DIR, SIGNERS, HOOK ---
    if kt in (hookapi.KEYLET_ACCOUNT, hookapi.KEYLET_OWNER_DIR,
              hookapi.KEYLET_SIGNERS, hookapi.KEYLET_HOOK):
        if b != 20:
            return hookapi.INVALID_ARGUMENT
        if c or d or e or f:
            return hookapi.INVALID_ARGUMENT
        accid = rt._read_memory(a, b)
        if kt == hookapi.KEYLET_ACCOUNT:
            kl = L.account_root_keylet(accid)
        elif kt == hookapi.KEYLET_OWNER_DIR:
            kl = L.owner_dir_keylet(accid)
        elif kt == hookapi.KEYLET_SIGNERS:
            kl = L.signers_keylet(accid)
        else:
            kl = L.hook_keylet(accid)

    # --- Account + uint32 sequence: OFFER, CHECK, ESCROW, NFT_OFFER, TICKET ---
    elif kt in (hookapi.KEYLET_OFFER, hookapi.KEYLET_CHECK,
                hookapi.KEYLET_ESCROW, hookapi.KEYLET_NFT_OFFER,
                hookapi.KEYLET_TICKET):
        if b != 20:
            return hookapi.INVALID_ARGUMENT
        if e or f:
            return hookapi.INVALID_ARGUMENT
        accid = rt._read_memory(a, b)
        seq = (c << 32) + d  # packed as two uint32s
        fn = {
            hookapi.KEYLET_OFFER: L.offer_keylet,
            hookapi.KEYLET_CHECK: L.check_keylet,
            hookapi.KEYLET_ESCROW: L.escrow_keylet,
            hookapi.KEYLET_NFT_OFFER: L.nft_offer_keylet,
            hookapi.KEYLET_TICKET: L.ticket_keylet,
        }[kt]
        kl = fn(accid, seq)

    # --- Trust line: two accounts + currency ---
    elif kt == hookapi.KEYLET_LINE:
        if b != 20 or d != 20:
            return hookapi.INVALID_ARGUMENT
        acc1 = rt._read_memory(a, 20)
        acc2 = rt._read_memory(c, 20)
        cur = rt._read_memory(e, f)
        kl = L.trust_line_keylet(acc1, acc2, cur)

    # --- Payment channel: src + dst + sequence ---
    elif kt == hookapi.KEYLET_PAYCHAN:
        if b != 20 or d != 20:
            return hookapi.INVALID_ARGUMENT
        src = rt._read_memory(a, 20)
        dst = rt._read_memory(c, 20)
        seq = (e << 32) + f
        kl = L.paychan_keylet(src, dst, seq)

    # --- Two accounts: DEPOSIT_PREAUTH ---
    elif kt == hookapi.KEYLET_DEPOSIT_PREAUTH:
        if b != 20 or d != 20:
            return hookapi.INVALID_ARGUMENT
        if e or f:
            return hookapi.INVALID_ARGUMENT
        owner = rt._read_memory(a, 20)
        auth = rt._read_memory(c, 20)
        kl = L.deposit_preauth_keylet(owner, auth)

    # --- 32-byte hash: HOOK_DEFINITION, CHILD, EMITTED, UNCHECKED ---
    elif kt in (hookapi.KEYLET_HOOK_DEFINITION, hookapi.KEYLET_CHILD,
                hookapi.KEYLET_EMITTED, hookapi.KEYLET_UNCHECKED):
        if b != 32:
            return hookapi.INVALID_ARGUMENT
        if c or d or e or f:
            return hookapi.INVALID_ARGUMENT
        key = rt._read_memory(a, 32)
        if kt == hookapi.KEYLET_HOOK_DEFINITION:
            kl = L.hook_definition_keylet(key)
        elif kt == hookapi.KEYLET_CHILD:
            kl = L.child_keylet(key)
        elif kt == hookapi.KEYLET_EMITTED:
            kl = L.emitted_txn_keylet(key)
        else:
            kl = L.unchecked_keylet(key)

    # --- Hook state: account + key + namespace ---
    elif kt == hookapi.KEYLET_HOOK_STATE:
        if b != 20 or d != 32 or f != 32:
            return hookapi.INVALID_ARGUMENT
        accid = rt._read_memory(a, 20)
        key = rt._read_memory(c, 32)
        ns = rt._read_memory(e, 32)
        kl = L.hook_state_keylet(accid, key, ns)

    # --- Hook state dir: account + namespace ---
    elif kt == hookapi.KEYLET_HOOK_STATE_DIR:
        if b != 20 or d != 32:
            return hookapi.INVALID_ARGUMENT
        if e or f:
            return hookapi.INVALID_ARGUMENT
        accid = rt._read_memory(a, 20)
        ns = rt._read_memory(c, 32)
        kl = L.hook_state_dir_keylet(accid, ns)

    # --- Global singletons: SKIP, AMENDMENTS, FEES, NEGATIVE_UNL ---
    elif kt == hookapi.KEYLET_SKIP:
        kl = L.skip_keylet()
    elif kt == hookapi.KEYLET_AMENDMENTS:
        kl = L.amendments_keylet()
    elif kt == hookapi.KEYLET_FEES:
        kl = L.fees_keylet()
    elif kt == hookapi.KEYLET_NEGATIVE_UNL:
        kl = L.negative_unl_keylet()

    else:
        return hookapi.INVALID_ARGUMENT

    rt._write_memory(write_ptr, kl)
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
