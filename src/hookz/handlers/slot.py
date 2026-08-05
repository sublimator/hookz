"""Slot system — real parsing with override support.

Slots hold serialized XRPL object bytes. slot_subfield/slot_subarray/slot_count
parse the actual data. Overrides (via rt._slot_overrides) take priority for
test-specific control.

Override keys:
    slot_data:{n}              — raw bytes in slot n
    slot_subfield:{p}:{fid}    — override return value for slot_subfield(p, fid, _)
    slot_count:{n}             — override return value for slot_count(n)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi
from hookz.xfl import float_to_xfl


_SLOT_MISSING = object()


def _get_slot_data(rt: HookRuntime, slot_no: int) -> bytes | None:
    """Get raw bytes stored in a slot, or None if slot doesn't exist."""
    data = rt._slot_overrides.get(f"slot_data:{slot_no}", _SLOT_MISSING)
    if data is _SLOT_MISSING:
        return None
    return data


def _set_slot_data(rt: HookRuntime, slot_no: int, data: bytes) -> None:
    """Store raw bytes into a slot."""
    rt._slot_overrides[f"slot_data:{slot_no}"] = data


def _walk_slot_fields(data: bytes):
    """Walk serialized fields in slot data. Thin wrapper around sto._walk_fields."""
    from hookz.handlers.sto import _walk_fields
    yield from _walk_fields(data)


# (type 14, field 1) — the byte that closes an STObject.
_OBJECT_END = 0xE1
# (type 15, field 1) — the byte that closes an STArray.
_ARRAY_END = 0xF1
_STI_OBJECT = 0xE
_STI_ARRAY = 0xF
_STI_VL = 0x7
_STI_VECTOR256 = 0x13


def _field_value_bytes(data: bytes, type_code: int, field_code: int,
                       offset: int, total_len: int,
                       pay_off: int, pay_len: int) -> bytes:
    """The value bytes the host serves for one field of `data`.

    Every host answer for a field is its `STBase::add` serialization, with
    exactly one exception — the write macro strips a leading length byte for
    accounts and nothing else:

        xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1908
            Serializer s;
            field->add(s);
            WRITE_WASM_MEMORY_OR_RETURN_AS_INT64(...,
                field->getSType() == STI_ACCOUNT);

    Concretely, from the field's serialized form inside `data`:

    - fixed-width types: the payload bytes;
    - `STI_ACCOUNT`: the payload without its length prefix;
    - other length-prefixed types (`STI_VL`, `STI_VECTOR256`): the prefix
      *kept* — `STBlob::add` serializes it as part of the value;
    - `STI_OBJECT` / `STI_ARRAY`: the contents only. The named outer header
      and the closing `E1`/`F1` belong to the *containing* object's
      serialization — `STObject::add` emits them around, not inside, the
      child's own `add` — so an empty array's value is empty.

    This is the single projection both `slot_subfield` and applied-callback
    direct reads use; the two views describe the same transaction upstream
    and may not disagree here.
    """
    header_len = 1 + (type_code >= 16) + (field_code >= 16)
    if type_code in (_STI_OBJECT, _STI_ARRAY):
        closing = _OBJECT_END if type_code == _STI_OBJECT else _ARRAY_END
        end = offset + total_len
        if total_len > header_len and data[end - 1] == closing:
            end -= 1
        return data[offset + header_len:end]
    if type_code in (_STI_VL, _STI_VECTOR256):
        return data[offset + header_len:offset + total_len]
    return data[pay_off:pay_off + pay_len]


def _walk_array_elements(data: bytes):
    """Walk top-level elements in a serialized array.

    Handles the outer array wrapper (F0-FF header + F1 end marker) if present,
    then yields each element as `(index, offset, length)`.

    An element is yielded as the object's *contents* — the fields inside it,
    with its own name header and closing marker removed. That is the level
    xahaud exposes: `slot_subarray` sets the slot entry to
    `parent_obj[array_id]` (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2202),
    an `STObject&`, and `slot_subfield` then asks that object for its own
    fields (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2251). So a Remit's
    sfAmounts element answers to `sfAmount`, not to `AmountEntry`.
    """
    start = 0
    end = len(data)

    # Unwrap array wrapper if present (STI_ARRAY = 0xF)
    if data[0] & 0xF0 == 0xF0:
        if data[0] == 0xF0:
            start += 2  # field code > 15: two header bytes
        else:
            start += 1  # field code <= 15: one header byte
        end -= 1  # Remove trailing 0xF1 (array end marker)

    if start >= end:
        return

    inner = data[start:end]
    from hookz.handlers.sto import _walk_fields
    for i, (_fid, tc, _fc, offset, total_len, pay_off, pay_len) in enumerate(
            _walk_fields(inner)):
        # Unwrap a named object element down to its fields. Anything else —
        # an array of bare values — is yielded whole, since there is no
        # wrapper to remove and inventing one would corrupt it.
        if (tc == _STI_OBJECT and pay_len > 0
                and inner[pay_off + pay_len - 1] == _OBJECT_END):
            yield i, start + pay_off, pay_len - 1
        else:
            yield i, start + offset, total_len


# ---------------------------------------------------------------------------
# slot_subfield
# ---------------------------------------------------------------------------

def slot_subfield(rt: HookRuntime, parent: int, field_id: int, new_slot: int) -> int:
    """Find a field in a parent slot's data and store it in new_slot.

    `new_slot == 0` means "allocate a free slot", the same convention every
    slot-emplacing call uses (`if (new_slot == 0) ... get_free_slot()`,
    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2253).

    Override: set rt._slot_overrides["slot_subfield:{parent}:{field_id}"]
    to force a specific return value.
    """
    # Check override first
    override_key = f"slot_subfield:{parent}:{field_id}"
    if override_key in rt._slot_overrides:
        result = rt._slot_overrides[override_key]
        # If override says DOESNT_EXIST, don't populate the slot
        if result == hookapi.DOESNT_EXIST:
            return hookapi.DOESNT_EXIST
        # Override returns the new slot number — but doesn't populate data
        # (test must also set slot_data if needed)
        return result

    # Real implementation: parse parent slot data
    parent_data = _get_slot_data(rt, parent)
    if parent_data is None:
        return hookapi.DOESNT_EXIST

    if new_slot == 0:
        from hookz.handlers.otxn import MAX_SLOTS
        new_slot = next((n for n in range(1, MAX_SLOTS + 1)
                         if _get_slot_data(rt, n) is None), 0)
        if new_slot == 0:
            return hookapi.NO_FREE_SLOTS

    try:
        for fid, type_code, fc, offset, total_len, pay_off, pay_len in _walk_slot_fields(parent_data):
            if fid == field_id:
                _set_slot_data(rt, new_slot, _field_value_bytes(
                    parent_data, type_code, fc, offset, total_len,
                    pay_off, pay_len))
                return new_slot
    except Exception:
        return hookapi.NOT_AN_OBJECT

    return hookapi.DOESNT_EXIST


# ---------------------------------------------------------------------------
# slot_count
# ---------------------------------------------------------------------------

def slot_count(rt: HookRuntime, slot_no: int) -> int:
    """Count elements in a serialized array slot.

    Override: set rt._slot_overrides["slot_count:{slot_no}"] to force a value.
    """
    # Check override first
    override_key = f"slot_count:{slot_no}"
    if override_key in rt._slot_overrides:
        return rt._slot_overrides[override_key]

    # Real implementation: parse slot data as array
    data = _get_slot_data(rt, slot_no)
    if data is None:
        return hookapi.DOESNT_EXIST

    try:
        count = 0
        for _ in _walk_array_elements(data):
            count += 1
        return count
    except Exception:
        return hookapi.NOT_AN_ARRAY


# ---------------------------------------------------------------------------
# slot_subarray
# ---------------------------------------------------------------------------

def slot_subarray(rt: HookRuntime, parent: int, idx: int, new_slot: int) -> int:
    """Extract element at index from an array slot into new_slot.

    Override: set rt._slot_overrides["slot_subarray:{parent}:{idx}"] to
    force a specific return value (for backwards compat with existing tests).
    """
    # Check override first
    override_key = f"slot_subarray:{parent}:{idx}"
    if override_key in rt._slot_overrides:
        return rt._slot_overrides[override_key]

    # Real implementation: parse parent slot data as array
    parent_data = _get_slot_data(rt, parent)
    if parent_data is None:
        return hookapi.DOESNT_EXIST

    try:
        for i, offset, total_len in _walk_array_elements(parent_data):
            if i == idx:
                _set_slot_data(rt, new_slot, parent_data[offset:offset + total_len])
                return new_slot
    except Exception:
        return hookapi.PARSE_ERROR

    return hookapi.DOESNT_EXIST


# ---------------------------------------------------------------------------
# slot (read raw bytes)
# ---------------------------------------------------------------------------

def _data_as_int64(data: bytes) -> int:
    """Convert up to 8 bytes of big-endian data to int64.

    Matches xahaud data_as_int64() from applyHook.cpp:
    - len > 8 → TOO_BIG
    - Reads as big-endian unsigned
    - If bit 63 is set → TOO_BIG (doesn't fit in signed int64)
    - Returns as int64
    """
    if len(data) > 8:
        return hookapi.TOO_BIG
    if len(data) == 0:
        return 0
    output = 0
    for i, b in enumerate(data):
        output += b << ((len(data) - 1 - i) * 8)
    if output & (1 << 63):
        return hookapi.TOO_BIG
    return output


def slot(rt: HookRuntime, write_ptr: int, write_len: int, slot_no: int) -> int:
    """Read raw bytes from a slot into WASM memory.

    When write_ptr=0, returns data_as_int64 (the WRITE_WASM_MEMORY_OR_RETURN_AS_INT64
    pattern from applyHook.cpp). write_len must also be 0 in this mode.
    """
    data = _get_slot_data(rt, slot_no)
    if data is None:
        return hookapi.DOESNT_EXIST
    if write_ptr == 0:
        if write_len != 0:
            return hookapi.INVALID_ARGUMENT
        return _data_as_int64(data)
    if len(data) > write_len:
        return hookapi.TOO_SMALL
    rt._write_memory(write_ptr, data)
    return len(data)


# ---------------------------------------------------------------------------
# slot_float
# ---------------------------------------------------------------------------

def slot_float(rt: HookRuntime, slot_no: int) -> int:
    """Read XFL from slot data.

    Interprets the slot bytes as a serialized amount and converts to XFL.
    """
    data = _get_slot_data(rt, slot_no)
    if data is None:
        return hookapi.DOESNT_EXIST
    if not data:
        return hookapi.INTERNAL_ERROR

    from hookz.handlers.float import float_sto_set

    # Use float_sto_set to deserialize — it handles headers, XRP/IOU, etc.
    rt._write_memory(0xF000, data)  # temp location
    return float_sto_set(rt, 0xF000, len(data))


# ---------------------------------------------------------------------------
# slot_size
# ---------------------------------------------------------------------------

def slot_size(rt: HookRuntime, slot_no: int) -> int:
    """Return the size of slot data in bytes."""
    data = _get_slot_data(rt, slot_no)
    if data is None:
        return hookapi.DOESNT_EXIST
    if not data:
        return hookapi.INTERNAL_ERROR
    return len(data)


# ---------------------------------------------------------------------------
# slot_set
# ---------------------------------------------------------------------------

def slot_set(rt: HookRuntime, read_ptr: int, read_len: int, slot_no: int) -> int:
    """Write data from WASM memory into a slot.

    If the data is a 34-byte keylet and rt.ledger contains that keylet,
    the slot is populated with the ledger object. Otherwise the raw bytes
    are stored directly.
    """
    if read_len not in (32, 34):
        return hookapi.INVALID_ARGUMENT
    if slot_no > 255:
        return hookapi.INVALID_ARGUMENT

    data = rt._read_memory(read_ptr, read_len)
    ledger = rt.ledger

    if data not in ledger:
        return hookapi.DOESNT_EXIST

    if slot_no == 0:
        for candidate in range(1, 256):
            if f"slot_data:{candidate}" not in rt._slot_overrides:
                slot_no = candidate
                break
        else:
            return hookapi.NO_FREE_SLOTS

    _set_slot_data(rt, slot_no, ledger[data])
    return slot_no


# ---------------------------------------------------------------------------
# slot_clear
# ---------------------------------------------------------------------------

def slot_clear(rt: HookRuntime, slot_no: int) -> int:
    """Clear a slot, removing all keys associated with it. Return 1."""
    key = f"slot_data:{slot_no}"
    if key not in rt._slot_overrides:
        return hookapi.DOESNT_EXIST
    # Remove all keys for this slot number
    to_remove = [k for k in rt._slot_overrides if k.endswith(f":{slot_no}")]
    for k in to_remove:
        del rt._slot_overrides[k]
    return 1


# ---------------------------------------------------------------------------
# slot_type (stub)
# ---------------------------------------------------------------------------

def slot_type(rt: HookRuntime, slot_no: int, flags: int) -> int:
    """Return the serialized field type of a slot.

    Stub: returns 0 (unknown type) when the slot exists.
    """
    data = _get_slot_data(rt, slot_no)
    if data is None:
        return hookapi.DOESNT_EXIST
    return 0


# ---------------------------------------------------------------------------
# meta_slot / xpop_slot
# ---------------------------------------------------------------------------

def meta_slot(rt: HookRuntime, slot_no: int) -> int:
    """Emplace the provisional transaction metadata into a slot.

    The refusals come in the host's order — no metadata first, before any
    slot question is asked:

        xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2378
            if (!hookCtx.result.provisionalMeta)
                return Unexpected(PREREQUISITE_NOT_MET);

    and that refusal is the *correct* answer for an ordinary strong
    execution, which runs before the transaction applies: there is no
    metadata yet. Metadata exists only for the executions the ledger runs
    after application — callbacks and weak TSH
    (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:2355-2365). Here that
    means `rt._callback_meta`, which `run_callback` sets to the serialized
    provisional TxMeta for the duration of the delivery.
    """
    from hookz.handlers.otxn import MAX_SLOTS

    if rt._callback_meta is None:
        return hookapi.PREREQUISITE_NOT_MET
    if slot_no > MAX_SLOTS:
        return hookapi.INVALID_ARGUMENT
    if slot_no == 0:
        slot_no = next((n for n in range(1, MAX_SLOTS + 1)
                        if _get_slot_data(rt, n) is None), 0)
        if slot_no == 0:
            return hookapi.NO_FREE_SLOTS
    _set_slot_data(rt, slot_no, rt._callback_meta)
    return slot_no


def xpop_slot(rt: HookRuntime, slot_no_ptr: int, slot_no_len: int) -> int:
    """Load an XPOP proof into a slot. Stub: returns DOESNT_EXIST."""
    return hookapi.DOESNT_EXIST
