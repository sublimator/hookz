"""State key-value store — state, state_set, state_foreign, state_foreign_set."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi


def state(rt: HookRuntime, write_ptr: int, write_len: int, kread_ptr: int, kread_len: int) -> int:
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    key = rt._read_memory(kread_ptr, kread_len)
    val = rt.state_db.get(key)
    if val is None:
        return hookapi.DOESNT_EXIST
    to_write = val[:write_len]
    rt._write_memory(write_ptr, to_write)
    return len(to_write)


def state_set(rt: HookRuntime, read_ptr: int, read_len: int, kread_ptr: int, kread_len: int) -> int:
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    key = rt._read_memory(kread_ptr, kread_len)
    if read_ptr == 0 and read_len == 0:
        rt.state_db.pop(key, None)
    else:
        val = rt._read_memory(read_ptr, read_len)
        rt.state_db[key] = val
    return read_len


def _get_foreign_state_db(rt: HookRuntime) -> dict[tuple[bytes, bytes, bytes], bytes]:
    """Get or create the foreign state database on rt."""
    if not hasattr(rt, "_foreign_state_db"):
        rt._foreign_state_db = {}
    return rt._foreign_state_db


def state_foreign(
    rt: HookRuntime,
    write_ptr: int, write_len: int,
    kread_ptr: int, kread_len: int,
    ns_ptr: int, ns_len: int,
    aread_ptr: int, aread_len: int,
) -> int:
    """Read state from another account.

    Keys the lookup on (account, namespace, key). The namespace is 32 bytes,
    the account is 20 bytes. Falls back to the local state_db when account
    matches rt.hook_account and namespace is zeros (for convenience).
    """
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    if ns_len != 0 and ns_len != 32:
        return hookapi.INVALID_ARGUMENT
    if aread_len != 0 and aread_len != 20:
        return hookapi.INVALID_ARGUMENT

    key = rt._read_memory(kread_ptr, kread_len)
    ns = rt._read_memory(ns_ptr, ns_len) if ns_len else b"\x00" * 32
    account = rt._read_memory(aread_ptr, aread_len) if aread_len else rt.hook_account

    db = _get_foreign_state_db(rt)
    val = db.get((account, ns, key))
    if val is None:
        return hookapi.DOESNT_EXIST
    to_write = val[:write_len]
    rt._write_memory(write_ptr, to_write)
    return len(to_write)


def state_foreign_set(
    rt: HookRuntime,
    read_ptr: int, read_len: int,
    kread_ptr: int, kread_len: int,
    ns_ptr: int, ns_len: int,
    aread_ptr: int, aread_len: int,
) -> int:
    """Write state to another account.

    read_ptr=0, read_len=0 is a delete operation.
    """
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if kread_len > 32:
        return hookapi.TOO_BIG
    if ns_len != 0 and ns_len != 32:
        return hookapi.INVALID_ARGUMENT
    if aread_len != 0 and aread_len != 20:
        return hookapi.INVALID_ARGUMENT

    key = rt._read_memory(kread_ptr, kread_len)
    ns = rt._read_memory(ns_ptr, ns_len) if ns_len else b"\x00" * 32
    account = rt._read_memory(aread_ptr, aread_len) if aread_len else rt.hook_account

    db = _get_foreign_state_db(rt)
    composite_key = (account, ns, key)

    if read_ptr == 0 and read_len == 0:
        db.pop(composite_key, None)
    else:
        val = rt._read_memory(read_ptr, read_len)
        db[composite_key] = val
    return read_len
