"""Transaction introspection — otxn_field, otxn_param, otxn_id, otxn_slot.

Hook parameter functions — hook_param, hook_param_set.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi

# xahaud:include/xrpl/hook/Enum.h:398
MAX_SLOTS = 255


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
    """
    key = rt._read_memory(kread_ptr, kread_len)
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    val = rt.tx_params.get(key)
    if val is None:
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
    rt._write_memory(write_ptr, b"\xAB" * min(write_len, 32))
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

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1566. The transaction always
    exists, so the only two failures are a slot number above `max_slots`
    (xahaud:include/xrpl/hook/Enum.h:398) and having no free slot to allocate
    when asked for one. Slot 0 means "pick one".

    The slot is populated, not merely reserved: a hook slots the transaction in
    order to navigate into it, and `slot_subfield`/`slot_count`/`slot_subarray`
    all read the bytes placed here.
    """
    from hookz.handlers.slot import _get_slot_data, _set_slot_data

    if slot_no > MAX_SLOTS:
        return hookapi.INVALID_ARGUMENT
    if slot_no == 0:
        slot_no = next((n for n in range(1, MAX_SLOTS + 1)
                        if _get_slot_data(rt, n) is None), 0)
        if slot_no == 0:
            return hookapi.NO_FREE_SLOTS
    _set_slot_data(rt, slot_no, serialized_otxn(rt))
    return slot_no
