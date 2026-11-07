"""Transaction introspection — otxn_field, otxn_param, otxn_id, otxn_slot.

Hook parameter functions — hook_param, hook_param_set.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi

# xahaud:include/xrpl/hook/Enum.h:402
MAX_SLOTS = 255

#: `cbak(0)` — the emitted transaction reached a ledger.
#:
#: This is **not** the same as "it worked". The ledger calls the callback when
#: `applied` is true, and
#:
#:     xahaud:src/xrpld/app/tx/detail/Transactor.cpp:2273
#:         applied = isTecClaim(result);
#:     xahaud:include/xrpl/protocol/TER.h:692
#:         inline bool isTecClaim(TER x) { return ((x) >= tecCLAIM); }
#:
#: so *every* `tec` counts — `tecNO_LINE` on a Remit to a staker with no
#: trustline, `tecUNFUNDED_PAYMENT` on a payout the account cannot cover. Those
#: arrive with ctx 0, indistinguishable from success, because the hook is handed
#: one bit and the bit does not mean what its name suggests.
CALLBACK_APPLIED = 0

#: `cbak(1)` — the emission never reached a ledger, so the ledger applies a
#: `ttEMIT_FAILURE` pseudo-transaction instead, whose own fields are
#: sfLedgerSequence and sfTransactionHash.
#:
#: xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1646
#:     isEmitFailure ? 1UL : 0UL
#: xahaud:include/xrpl/protocol/detail/transactions.macro:622
#:     TRANSACTION(ttEMIT_FAILURE, 103, EmitFailure, ({
#:         {sfLedgerSequence, soeREQUIRED},
#:         {sfTransactionHash, soeREQUIRED},
#:     }))
#:
#: The hook does not read the pseudo's fields, though. Under fix20261005 a
#: failure callback reads the *original emission* — its fields, its type, its
#: slot — and the pseudo's two are DOESNT_EXIST. Without the fix this
#: delivery crashes the node, and `HookRuntime.callback` raises `NodeCrash`
#: rather than model it.
CALLBACK_NOT_APPLIED = 1


def _write_or_return_int64(rt: HookRuntime, write_ptr: int, write_len: int,
                           data: bytes, is_account: bool = False) -> int:
    """WRITE_WASM_MEMORY_OR_RETURN_AS_INT64 pattern from applyHook.cpp.

    When write_ptr=0: returns data_as_int64 (big-endian bytes → int64).
    Otherwise: writes to WASM memory, returns byte count.
    is_account: if True, strips the leading VL length byte.
    """
    if is_account and len(data) > 0:
        data = data[1:]
    if len(data) == 0:
        return 0
    if write_ptr == 0:
        if write_len != 0:
            return hookapi.INVALID_ARGUMENT
        from hookz.handlers.slot import _data_as_int64
        return _data_as_int64(data)
    if len(data) > write_len:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, data)
    return len(data)


def otxn_field(rt: HookRuntime, write_ptr: int, write_len: int, field_id: int) -> int:
    """A field of the originating transaction.

    `rt.otxn_fields` is consulted first, so a transaction can carry any field a
    hook reads — sfFlags, sfAmount, sfDestination, sfSourceTag — with the
    built-ins below serving the two the runtime models directly. DOESNT_EXIST
    is reserved for a field the transaction genuinely does not have, since to a
    hook that answer is indistinguishable from "this harness cannot say".

    **In a callback, both modes read the emission.** Applied, the transaction
    being applied *is* the emission. Not applied, it is the `ttEMIT_FAILURE`
    pseudo-transaction, and under fix20261005 the host takes presence and
    value from the original emission instead:

        xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1591
            if (hookCtx.emitFailure &&
                hookCtx.applyCtx.view().rules().enabled(fix20261005))
            {
                if (!hookCtx.emitFailure->isFieldPresent(fieldType))
                    return Unexpected(DOESNT_EXIST);
                return &hookCtx.emitFailure->getField(fieldType);
            }

    `emitFailure` is set only when `isCallback && (wasmParam & 1)`
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1049), and is the
    emitted transaction captured before the pseudo erased its entry
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1057). So a failure
    callback reads sfDestination and sfAmount — what an undo needs — and the
    pseudo's sfLedgerSequence and sfTransactionHash are DOESNT_EXIST, because
    the emission does not carry them. `run_callback` loads the emission into
    `rt.otxn_fields` in both modes, so nothing here branches on the mode.

    The pre-fix branch below that one checks presence on the pseudo
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1599) — the "only two
    fields readable" picture — but no hook ever reached it: the callback
    crashed the node before running (see `HookRuntime.callback`).
    """
    override = rt.otxn_fields.get(field_id)
    if override is not None:
        return _write_or_return_int64(rt, write_ptr, write_len, override)
    if field_id == hookapi.sfAccount:
        data = rt.otxn_account
        return _write_or_return_int64(rt, write_ptr, write_len, data)
    if field_id == hookapi.sfTransactionType:
        data = rt.otxn_type.to_bytes(2, "big")
        return _write_or_return_int64(rt, write_ptr, write_len, data)
    return hookapi.DOESNT_EXIST


def otxn_param(rt: HookRuntime, write_ptr: int, write_len: int, kread_ptr: int, kread_len: int) -> int:
    """Read a parameter carried by the originating transaction.

    Separate namespace from the hook's install parameters (`rt.params`), as on
    chain: the same name may exist in both and they do not collide.

    An empty value is DOESNT_EXIST, as is a parameter with no value at all:

        xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1680
            if (!param.isFieldPresent(sfHookParameterValue))
                return Unexpected(DOESNT_EXIST);
            auto const& val = param.getFieldVL(sfHookParameterValue);
            if (val.empty())
                return Unexpected(DOESNT_EXIST);

    so `rt.tx_params[name] = b""` reads to the hook exactly like an absent
    name — the same answer `hook_param` gives an emptied override.
    """
    key = rt._read_memory(kread_ptr, kread_len)
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    val = rt.tx_params.get(key)
    if not val:
        return hookapi.DOESNT_EXIST
    if len(val) > write_len:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, val)
    return len(val)


def hook_param(rt: HookRuntime, write_ptr: int, write_len: int, kread_ptr: int, kread_len: int) -> int:
    """Read a hook parameter by key.

    Checks param overrides first (set by hook_param_set from prior hooks
    in the chain), then falls back to rt.params (the hook's own parameters).
    """
    key = rt._read_memory(kread_ptr, kread_len)
    key_len = len(key)
    if key_len < 1:
        return hookapi.TOO_SMALL
    if key_len > 32:
        return hookapi.TOO_BIG

    # Check overrides first (set by hook_param_set)
    # Note: C++ only checks overrides keyed by the current hook's hash.
    # We search all hashes for convenience — tests don't need to know
    # the exact hook hash. This is an intentional divergence.
    overrides = rt._param_overrides
    if overrides:
        for _hash, params in overrides.items():
            if key in params:
                val = params[key]
                if len(val) == 0:
                    # Empty override means "deleted"
                    return hookapi.DOESNT_EXIST
                to_write = val[:write_len]
                rt._write_memory(write_ptr, to_write)
                return len(to_write)

    # Fall back to hook's own params
    val = rt.params.get(key)
    if val is None:
        return hookapi.DOESNT_EXIST
    to_write = val[:write_len]
    rt._write_memory(write_ptr, to_write)
    return len(to_write)


def hook_param_set(
    rt: HookRuntime,
    read_ptr: int, read_len: int,
    kread_ptr: int, kread_len: int,
    hread_ptr: int, hread_len: int,
) -> int:
    """Set a hook parameter override for another hook in the chain.

    Stores the override in rt._param_overrides keyed by (hook_hash, param_name).
    The C++ impl requires kread_len in [1, 32], hread_len == 32, read_len <= 256.
    """
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    if hread_len != 32:
        return hookapi.INVALID_ARGUMENT
    if read_len > 256:
        return hookapi.TOO_BIG

    key = rt._read_memory(kread_ptr, kread_len)
    value = rt._read_memory(read_ptr, read_len) if read_len > 0 else b""
    hook_hash = rt._read_memory(hread_ptr, hread_len)

    hook_hash_key = bytes(hook_hash)
    if hook_hash_key not in rt._param_overrides:
        rt._param_overrides[hook_hash_key] = {}
    rt._param_overrides[hook_hash_key][key] = value
    return len(value)


def otxn_type(rt: HookRuntime) -> int:
    """Return the originating transaction type."""
    return rt.otxn_type


def otxn_id(rt: HookRuntime, write_ptr: int, write_len: int, flags: int) -> int:
    """The hash of the originating transaction.

    During a callback both modes answer with the *emitted* transaction's hash.
    Applied, the transaction being applied is the emission itself, so its
    transaction ID is the answer; not applied, the `ttEMIT_FAILURE`
    pseudo-transaction carries the failed emission's hash as
    `sfTransactionHash`, and that is served unless `flags` asks for the
    pseudo-transaction's own ID:

        xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1612
            (hookCtx.emitFailure && !flags
                 ? hookCtx.applyCtx.tx.getFieldH256(sfTransactionHash)
                 : hookCtx.applyCtx.tx.getTransactionID());

    `run_callback` sets `rt.otxn_id_val` to that hash for the delivery. Unset
    — an ordinary run — the historical sentinel fill stays, so a hook that
    stores the ID gets a stable 32-byte value without every test inventing
    one. The `flags` distinction is not modelled: the mock has no
    pseudo-transaction with an ID of its own to serve.
    """
    val = rt.otxn_id_val
    if val is None:
        rt._write_memory(write_ptr, b"\xAB" * min(write_len, 32))
        return 32
    if len(val) != 32:
        # A short or long value here would make otxn_id and
        # otxn_field(sfTransactionHash) disagree about one purported
        # Hash256 — a state no ledger can serve. A malformed-id guard shape
        # belongs in a handler override, where its non-ledger status is
        # explicit.
        raise ValueError(
            f"rt.otxn_id_val must be exactly 32 bytes (Hash256), got "
            f"{len(val)}")
    if write_len < 32:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, val)
    return 32


def serialized_otxn(rt: HookRuntime) -> bytes:
    """The originating transaction as bytes, however the test described it.

    `rt.otxn_blob` wins when set — a test that built a real transaction with
    `xrpl.core.binarycodec.encode` has said everything there is to say, and
    re-deriving it here could only lose detail.

    Otherwise it is assembled from the same three places `otxn_field` answers
    from, so the two cannot disagree about what arrived. A hook that reads
    sfFlags directly and a hook that slots the transaction and navigates to it
    see one transaction, not two.
    """
    from hookz.xrpl.txn_builder import serialize_fields

    if rt.otxn_blob is not None:
        return rt.otxn_blob
    fields = dict(rt.otxn_fields)
    fields.setdefault(hookapi.sfTransactionType, rt.otxn_type.to_bytes(2, "big"))
    fields.setdefault(hookapi.sfAccount, rt.otxn_account)
    return serialize_fields(fields)


def otxn_slot(rt: HookRuntime, slot_no: int) -> int:
    """Emplace the originating transaction into a slot.

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1631. The transaction always
    exists, so the only two failures are a slot number above `max_slots`
    (xahaud:include/xrpl/hook/Enum.h:402) and having no free slot to allocate
    when asked for one. Slot 0 means "pick one".

    The slot is populated, not merely reserved: a hook slots the transaction in
    order to navigate into it, and `slot_subfield`/`slot_count`/`slot_subarray`
    all read the bytes placed here.

    In a failure callback the slotted object is `*(hookCtx.emitFailure)`
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1649): under fix20261005
    the original emission itself, not the ledger entry that held it — so
    `run_callback` puts the emitted blob in `rt.otxn_blob` for both modes.
    """
    from hookz.handlers.slot import _get_slot_data, _set_slot_data, _STI_OBJECT

    if slot_no > MAX_SLOTS:
        return hookapi.INVALID_ARGUMENT
    if slot_no == 0:
        slot_no = next((n for n in range(1, MAX_SLOTS + 1)
                        if _get_slot_data(rt, n) is None), 0)
        if slot_no == 0:
            return hookapi.NO_FREE_SLOTS
    _set_slot_data(rt, slot_no, serialized_otxn(rt), stype=_STI_OBJECT)
    return slot_no
