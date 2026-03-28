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


def _walk_array_elements(data: bytes):
    """Walk top-level elements in a serialized array.

    Handles the outer array wrapper (F0-FF header + F1 end marker) if present,
    then yields each inner object element.
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
    for i, (fid, _tc, _fc, offset, total_len, _po, _pl) in enumerate(_walk_fields(inner)):
        yield i, start + offset, total_len


# ---------------------------------------------------------------------------
# slot_subfield
# ---------------------------------------------------------------------------

def slot_subfield(rt: HookRuntime, parent: int, field_id: int, new_slot: int) -> int:
    """Find a field in a parent slot's data and store it in new_slot.

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

    try:
        for fid, type_code, _fc, offset, total_len, pay_off, pay_len in _walk_slot_fields(parent_data):
            if fid == field_id:
                # For arrays (type 0xF), store the whole field including header
                if type_code == 0xF:
                    _set_slot_data(rt, new_slot, parent_data[offset:offset + total_len])
                else:
                    # Store just the payload (what slot() would return)
                    _set_slot_data(rt, new_slot, parent_data[pay_off:pay_off + pay_len])
                return new_slot
    except Exception:
        return hookapi.PARSE_ERROR

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

def slot(rt: HookRuntime, write_ptr: int, write_len: int, slot_no: int) -> int:
    """Read raw bytes from a slot into WASM memory."""
    data = _get_slot_data(rt, slot_no)
    if data is None:
        return hookapi.DOESNT_EXIST
    to_write = data[:write_len]
    rt._write_memory(write_ptr, to_write)
    return len(to_write)


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
    if read_len > 0:
        data = rt._read_memory(read_ptr, read_len)
        # Check if this is a keylet lookup
        ledger = getattr(rt, "ledger", None)
        if ledger and read_len == 34 and data in ledger:
            _set_slot_data(rt, slot_no, ledger[data])
        else:
            _set_slot_data(rt, slot_no, data)
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
# meta_slot / xpop_slot (stubs)
# ---------------------------------------------------------------------------

def meta_slot(rt: HookRuntime, slot_no: int) -> int:
    """Load transaction metadata into a slot. Stub: returns slot_no."""
    return slot_no


def xpop_slot(rt: HookRuntime, slot_no_ptr: int, slot_no_len: int) -> int:
    """Load an XPOP proof into a slot. Stub: returns DOESNT_EXIST."""
    return hookapi.DOESNT_EXIST
