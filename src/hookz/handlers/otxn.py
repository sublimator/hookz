"""Transaction introspection — otxn_field, otxn_param, otxn_id, otxn_slot.

Hook parameter functions — hook_param, hook_param_set.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi


def otxn_field(rt: HookRuntime, write_ptr: int, write_len: int, field_id: int) -> int:
    if field_id == hookapi.sfAccount:
        rt._write_memory(write_ptr, rt.otxn_account[:write_len])
        return 20
    if field_id == hookapi.sfTransactionType:
        tt = rt.otxn_type.to_bytes(2, "big")
        rt._write_memory(write_ptr, tt[:write_len])
        return 2
    return hookapi.DOESNT_EXIST


def otxn_param(rt: HookRuntime, write_ptr: int, write_len: int, kread_ptr: int, kread_len: int) -> int:
    key = rt._read_memory(kread_ptr, kread_len)
    val = rt.params.get(key)
    if val is None:
        return hookapi.DOESNT_EXIST
    to_write = val[:write_len]
    rt._write_memory(write_ptr, to_write)
    return len(to_write)


def hook_param(rt: HookRuntime, write_ptr: int, write_len: int, kread_ptr: int, kread_len: int) -> int:
    """Read a hook parameter by key.

    Checks param overrides first (set by hook_param_set from prior hooks
    in the chain), then falls back to rt.params (the hook's own parameters).
    """
    key = rt._read_memory(kread_ptr, kread_len)
    if key_len := len(key):
        if key_len < 1:
            return hookapi.TOO_SMALL
        if key_len > 32:
            return hookapi.TOO_BIG

    # Check overrides first (set by hook_param_set)
    overrides = getattr(rt, "_param_overrides", {})
    if overrides:
        # Search all hook hashes for this key
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

    if not hasattr(rt, "_param_overrides"):
        rt._param_overrides = {}
    hook_hash_key = bytes(hook_hash)
    if hook_hash_key not in rt._param_overrides:
        rt._param_overrides[hook_hash_key] = {}
    rt._param_overrides[hook_hash_key][key] = value
    return len(value)


def otxn_id(rt: HookRuntime, write_ptr: int, write_len: int, flags: int) -> int:
    rt._write_memory(write_ptr, b"\xAB" * min(write_len, 32))
    return 32


def otxn_slot(rt: HookRuntime, slot_no: int) -> int:
    return slot_no
