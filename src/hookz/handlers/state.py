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
    if write_ptr == 0:
        from hookz.handlers.slot import _data_as_int64
        return _data_as_int64(val)
    if len(val) > write_len:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, val)
    return len(val)


def _journal(rt: HookRuntime, scope: str, account: bytes, namespace: bytes,
             key: bytes, value: bytes | None, result: int) -> None:
    """Record a performed write/delete on the runtime's state journal."""
    from hookz.runtime import StateWrite

    rt.state_journal.append(StateWrite(
        scope=scope,
        account=account,
        namespace=namespace,
        key=key,
        value=value,
        result=result,
        export=rt._current_export,
    ))


def _state_set_error(rt: HookRuntime, read_ptr: int, read_len: int,
                     kread_ptr: int, kread_len: int,
                     ns_ptr: int = 0, ns_len: int = 0,
                     aread_ptr: int = 0, aread_len: int = 0) -> int | None:
    """The admission half of `state_set`/`state_foreign_set`, shared with the
    fault layer.

    One implementation for both, because the host has one: `state_set` *is* a
    call to the `state_foreign_set` wrapper with four zeros
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1257). The host refuses
    malformed arguments before any question of whether the write itself would
    succeed, in that wrapper's order
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1293-1322):

    1. the value buffer's bounds — skipped for the zero/zero spelling, which
       is a *bounds-check exemption* and not, by itself, what makes a call a
       delete (see `state_set` for the delete test the host actually uses);
    2. the key width, then the namespace and account widths;
    3. the key buffer's bounds, then the namespace/account pairing rule, then
       the namespace and account buffers' bounds.

    The value size cap sits later in the host (…:1334), behind an account
    lookup that cannot fail here, and no overlapping failure distinguishes
    that from checking it last. A wrapper that re-implemented any of this
    would drift from it.
    """
    from hookz.handlers.core import _not_in_bounds

    if not (read_ptr == 0 and read_len == 0):
        if _not_in_bounds(rt, read_ptr, read_len):
            return hookapi.OUT_OF_BOUNDS
    if kread_len > 32:
        return hookapi.TOO_BIG
    if kread_len < 1:
        return hookapi.TOO_SMALL
    if ns_len != 0 and ns_len != 32:
        return hookapi.INVALID_ARGUMENT
    if aread_len != 0 and aread_len != 20:
        return hookapi.INVALID_ARGUMENT
    if _not_in_bounds(rt, kread_ptr, kread_len):
        return hookapi.OUT_OF_BOUNDS
    # a namespace may be omitted if and only if this is a local set
    if ns_ptr == 0 and ns_len == 0 and not (aread_ptr == 0 and aread_len == 0):
        return hookapi.INVALID_ARGUMENT
    if ((ns_len and _not_in_bounds(rt, ns_ptr, ns_len))
            or (aread_len and _not_in_bounds(rt, aread_ptr, aread_len))):
        return hookapi.OUT_OF_BOUNDS
    if read_len > 256:
        return hookapi.TOO_BIG
    return None


def _is_delete(read_len: int) -> bool:
    """Does this admitted `state_set` erase the entry rather than write it?

    The host's test is the *blob*, not the pointer: `state_foreign_set` slices
    `[memory + read_ptr, memory + read_ptr + read_len)`
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1358) and `setHookState`
    deletes when that slice is empty — "if the blob is nil then delete the
    entry if it exists"
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:903). So any zero length is a
    delete, however the caller spelled the pointer. The zero/zero form is only
    the one spelling that also skips the value buffer's bounds check (…:1293);
    reading it as the definition made `state_set(ptr, 0, key)` store an empty
    value where the network erases the entry.
    """
    return read_len == 0


def state_set(rt: HookRuntime, read_ptr: int, read_len: int, kread_ptr: int, kread_len: int) -> int:
    err = _state_set_error(rt, read_ptr, read_len, kread_ptr, kread_len)
    if err is not None:
        return err
    key = rt._read_memory(kread_ptr, kread_len)
    if _is_delete(read_len):
        rt.state_db.pop(key, None)
        val = None
    else:
        val = rt._read_memory(read_ptr, read_len)
        rt.state_db[key] = val
    _journal(rt, "local", rt.hook_account, rt.hook_namespace, key, val,
             read_len)
    return read_len


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
    is_foreign = aread_ptr != 0
    if not is_foreign and aread_len != 0:
        return hookapi.INVALID_ARGUMENT
    if is_foreign and aread_len != 20:
        return hookapi.INVALID_ARGUMENT

    if not is_foreign and ns_len == 0:
        pass  # local account uses default namespace
    elif ns_len != 32:
        return hookapi.INVALID_ARGUMENT

    key = rt._read_memory(kread_ptr, kread_len)
    ns = rt._read_memory(ns_ptr, ns_len) if ns_len else b"\x00" * 32
    account = rt._read_memory(aread_ptr, aread_len) if aread_len else rt.hook_account

    db = rt._foreign_state_db
    val = db.get((account, ns, key))
    if val is None:
        return hookapi.DOESNT_EXIST
    if write_ptr == 0:
        from hookz.handlers.slot import _data_as_int64
        return _data_as_int64(val)
    if len(val) > write_len:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, val)
    return len(val)


def state_foreign_set(
    rt: HookRuntime,
    read_ptr: int, read_len: int,
    kread_ptr: int, kread_len: int,
    ns_ptr: int, ns_len: int,
    aread_ptr: int, aread_len: int,
) -> int:
    """Write state to another account.

    A zero read_len is a delete operation — see `_is_delete`. Admission is
    `_state_set_error`, the same implementation `state_set` uses, because the
    host reaches this wrapper by both routes.
    """
    err = _state_set_error(rt, read_ptr, read_len, kread_ptr, kread_len,
                           ns_ptr, ns_len, aread_ptr, aread_len)
    if err is not None:
        return err

    key = rt._read_memory(kread_ptr, kread_len)
    ns = rt._read_memory(ns_ptr, ns_len) if ns_len else b"\x00" * 32
    account = rt._read_memory(aread_ptr, aread_len) if aread_len else rt.hook_account

    db = rt._foreign_state_db
    composite_key = (account, ns, key)

    if _is_delete(read_len):
        db.pop(composite_key, None)
        val = None
    else:
        val = rt._read_memory(read_ptr, read_len)
        db[composite_key] = val
    _journal(rt, "foreign", account, ns, key, val, read_len)
    return read_len
