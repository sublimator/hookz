"""Slot system — slot, slot_set, slot_subfield, slot_count, slot_subarray, slot_float, slot_size."""

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi
from hookz.xfl import float_to_xfl


def slot_subfield(rt: HookRuntime, parent: int, field_id: int, new_slot: int) -> int:
    key = f"slot_subfield:{parent}:{field_id}"
    if key in rt._slot_overrides:
        return rt._slot_overrides[key]
    return hookapi.DOESNT_EXIST


def slot_count(rt: HookRuntime, slot_no: int) -> int:
    return rt._slot_overrides.get(f"slot_count:{slot_no}", 0)


def slot_subarray(rt: HookRuntime, parent: int, idx: int, new_slot: int) -> int:
    return new_slot


def slot(rt: HookRuntime, write_ptr: int, write_len: int, slot_no: int) -> int:
    data = rt._slot_overrides.get(f"slot_data:{slot_no}", b"")
    if not data:
        return hookapi.DOESNT_EXIST
    to_write = data[:write_len]
    rt._write_memory(write_ptr, to_write)
    return len(to_write)


def slot_float(rt: HookRuntime, slot_no: int) -> int:
    """Read XFL from slot data.

    The slot must contain serialized amount bytes. This converts the raw
    slot data to an XFL integer using the same approach as the C++ impl:
    interpret the bytes as a big-endian amount and normalize to XFL.
    """
    key = f"slot_data:{slot_no}"
    if key not in rt._slot_overrides:
        return hookapi.DOESNT_EXIST
    data = rt._slot_overrides[key]
    if not data:
        return hookapi.INTERNAL_ERROR
    # Interpret slot data as a big-endian 64-bit drops value and convert to XFL
    drops = int.from_bytes(data[:8], "big")
    # Strip the positive/negative flag bits (top byte flags)
    drops = drops & 0x00FFFFFFFFFFFFFF
    if drops == 0:
        return 0
    return float_to_xfl(float(drops))


def slot_size(rt: HookRuntime, slot_no: int) -> int:
    """Return the size of slot data in bytes."""
    key = f"slot_data:{slot_no}"
    if key not in rt._slot_overrides:
        return hookapi.DOESNT_EXIST
    data = rt._slot_overrides[key]
    if not data:
        return hookapi.INTERNAL_ERROR
    return len(data)


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


def slot_type(rt: HookRuntime, slot_no: int, flags: int) -> int:
    """Return the serialized field type of a slot.

    This is a stub that returns 0 (unknown type) when the slot exists,
    or DOESNT_EXIST when it does not.
    """
    key = f"slot_data:{slot_no}"
    if key not in rt._slot_overrides:
        return hookapi.DOESNT_EXIST
    # Stub: return 0 indicating unknown/default field type
    return 0


def meta_slot(rt: HookRuntime, slot_no: int) -> int:
    """Load transaction metadata into a slot.

    Stub: returns slot_no. The real implementation loads provisional
    transaction metadata into the slot system.
    """
    return slot_no


def xpop_slot(rt: HookRuntime, slot_no_ptr: int, slot_no_len: int) -> int:
    """Load an XPOP proof into a slot.

    This is very specialized (requires an Import transaction with XPOP
    proof data).  Stub returns DOESNT_EXIST by default.
    """
    return hookapi.DOESNT_EXIST


def slot_set(rt: HookRuntime, read_ptr: int, read_len: int, slot_no: int) -> int:
    if read_len > 0:
        data = rt._read_memory(read_ptr, read_len)
        rt._slot_overrides[f"slot_data:{slot_no}"] = data
    return slot_no
