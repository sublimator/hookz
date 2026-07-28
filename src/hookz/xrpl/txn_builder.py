"""Serialize a field map back into an STObject.

The inverse of `txn_parser`, and it exists for one reason: `otxn_slot` hands a
hook the *whole* originating transaction, and everything the hook does next —
`slot_subfield`, `slot_count`, `slot_subarray` — parses those bytes. Serving a
transaction therefore means being able to serialize one.

Headers and the variable-length prefix come from xrpl-py rather than from a
local implementation of the same rules, because the same library parses them
back out. A writer that disagreed with the reader would produce bytes that
round-trip inside hookz and nowhere else.
"""

from __future__ import annotations

from collections.abc import Mapping

from hookz.xrpl.xrpl_patch import patch_xahau_definitions

patch_xahau_definitions()


def _is_variable_length(header) -> bool:
    """Does this field carry a length prefix between header and payload?

    Unknown to the definitions — a field xrpl-py has never heard of — is
    treated as not length-prefixed, which is the only answer available. It is
    also the safe one: the alternative writes a prefix the reader will not
    expect and corrupts every field after it, rather than just this one.
    """
    from xrpl.core.binarycodec.definitions import (
        get_field_instance, get_field_name_from_header,
    )
    try:
        name = get_field_name_from_header(header)
    except Exception:                                          # noqa: BLE001
        return False
    if name is None:
        return False
    try:
        return get_field_instance(name).is_variable_length_encoded
    except Exception:                                          # noqa: BLE001
        return False


def serialize_field(field_id: int, payload: bytes) -> bytes:
    """One field: header, a length prefix if the type takes one, then payload.

    `field_id` is the hook-API sfCode — `(type_code << 16) | field_code`, the
    same encoding `sto.py` decodes (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1721
    reads them the same way).
    """
    from xrpl.core.binarycodec.binary_wrappers.binary_serializer import (
        _encode_variable_length_prefix,
    )
    from xrpl.core.binarycodec.definitions.field_header import FieldHeader

    header = FieldHeader(field_id >> 16, field_id & 0xFFFF)
    out = bytes(header)
    if _is_variable_length(header):
        out += _encode_variable_length_prefix(len(payload))
    return out + payload


def serialize_fields(fields: Mapping[int, bytes]) -> bytes:
    """A whole object, in canonical field order.

    Canonical order is ascending `(type_code, field_code)`, and an sfCode is
    `type_code << 16 | field_code` — so sorting the keys numerically *is* the
    canonical sort, with no separate comparator to keep in step with the
    encoding.
    """
    out = bytearray()
    for field_id in sorted(fields):
        out += serialize_field(field_id, fields[field_id])
    return bytes(out)
