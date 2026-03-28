"""STO (Serialized Transaction Object) handlers — subfield, subarray, emplace, erase, validate."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hookz import hookapi
from hookz.xrpl.xrpl_patch import patch_xahau_definitions

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

patch_xahau_definitions()


def _field_id_from_header(type_code: int, field_code: int) -> int:
    """Encode type_code and field_code into a field_id matching xahaud convention."""
    return (type_code << 16) | field_code


def _walk_fields(data: bytes):
    """Walk serialized fields, yielding field info tuples.

    Yields: (field_id, type_code, field_code, offset, total_len, payload_offset, payload_len)

    - offset: byte offset of the entire field (including header) within data
    - total_len: total bytes consumed by this field (header + VL prefix + payload)
    - payload_offset: byte offset of just the payload data within data
    - payload_len: byte length of just the payload data (excluding header and VL prefix)

    Uses BinaryParser to parse each field header and value, tracking byte offsets.
    """
    from xrpl.core.binarycodec.binary_wrappers import BinaryParser

    hex_str = data.hex()
    parser = BinaryParser(hex_str)
    total = len(data)

    while not parser.is_end():
        offset = total - len(parser)
        field = parser.read_field()
        header_len = len(bytes(field.header))
        # For VL-encoded fields, the parser reads a length prefix before
        # the actual payload. We need to know where the raw payload starts.
        pre_value_pos = total - len(parser)
        parser.read_field_value(field)
        end_offset = total - len(parser)
        field_len = end_offset - offset

        if field.is_variable_length_encoded:
            # VL prefix sits between header and payload data.
            # Determine VL prefix length from the first byte after the header.
            vl_byte = data[pre_value_pos]
            if vl_byte <= 192:
                vl_prefix_len = 1
            elif vl_byte <= 240:
                vl_prefix_len = 2
            else:
                vl_prefix_len = 3
            payload_data_len = end_offset - pre_value_pos - vl_prefix_len
            payload_data_offset = offset + header_len + vl_prefix_len
        else:
            payload_data_offset = offset + header_len
            payload_data_len = field_len - header_len

        type_code = field.header.type_code
        field_code = field.header.field_code
        fid = _field_id_from_header(type_code, field_code)
        yield fid, type_code, field_code, offset, field_len, payload_data_offset, payload_data_len


def sto_subfield(rt: HookRuntime, read_ptr: int, read_len: int, field_id: int) -> int:
    """Find a field in a serialized object, return packed (offset << 32 | length).

    For array fields (type 0xF), returns offset and length of the entire field
    including its header. For all others, returns offset and length of the payload only.
    """
    if read_len < 2:
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)

    try:
        for fid, type_code, _fc, offset, total_len, pay_off, pay_len in _walk_fields(data):
            if fid == field_id:
                if type_code == 0xF:  # STI_ARRAY — return fully formed
                    return (offset << 32) | total_len
                else:
                    return (pay_off << 32) | pay_len
    except Exception:
        return hookapi.PARSE_ERROR

    return hookapi.DOESNT_EXIST


def sto_subarray(rt: HookRuntime, read_ptr: int, read_len: int, index: int) -> int:
    """Find element at index in a serialized array, return packed (offset << 32 | length).

    If the data starts with an array wrapper byte (0xF0-0xFF), unwrap it first.
    """
    if read_len < 2:
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)

    # Unwrap array wrapper if present (STI_ARRAY = 0xF)
    start = 0
    end = len(data)
    if data[0] & 0xF0 == 0xF0:
        if data[0] == 0xF0:
            # Field code > 15: two header bytes
            start += 2
        else:
            # Field code <= 15: one header byte
            start += 1
        end -= 1  # Remove trailing 0xF1 (array end marker)

    if start >= end:
        return hookapi.PARSE_ERROR

    inner = data[start:end]

    try:
        for i, (fid, _tc, _fc, offset, total_len, _po, _pl) in enumerate(_walk_fields(inner)):
            if i == index:
                # Return offset relative to original data
                actual_offset = start + offset
                return (actual_offset << 32) | total_len
    except Exception:
        return hookapi.PARSE_ERROR

    return hookapi.DOESNT_EXIST


def sto_emplace(
    rt: HookRuntime,
    write_ptr: int,
    write_len: int,
    sread_ptr: int,
    sread_len: int,
    fread_ptr: int,
    fread_len: int,
    field_id: int,
) -> int:
    """Insert or replace a field in a serialized object. Write result to output buffer.

    If fread_ptr == 0 and fread_len == 0, this is a delete operation.
    Fields are inserted at their canonical (sorted by field_id) position.
    """
    if sread_len < 2:
        return hookapi.TOO_SMALL
    if sread_len > 1024 * 16:
        return hookapi.TOO_BIG

    is_delete = fread_ptr == 0 and fread_len == 0

    if not is_delete:
        if fread_len < 2:
            return hookapi.TOO_SMALL
        if fread_len > 4096:
            return hookapi.TOO_BIG

    if not is_delete and write_len < sread_len + fread_len:
        return hookapi.TOO_SMALL

    source = rt._read_memory(sread_ptr, sread_len)
    field_bytes = None if is_delete else rt._read_memory(fread_ptr, fread_len)

    # Parse source object fields, tracking where to inject/replace
    inject_start = len(source)  # default: append at end
    inject_end = len(source)

    try:
        for fid, _tc, _fc, offset, total_len, _po, _pl in _walk_fields(source):
            if fid == field_id:
                # Found existing field — replace (or delete)
                inject_start = offset
                inject_end = offset + total_len
                break
            elif fid > field_id:
                # Insert before this field (canonical ordering)
                inject_start = offset
                inject_end = offset
                break
    except Exception:
        return hookapi.PARSE_ERROR

    # Build output: [before inject] + [new field or nothing] + [after inject]
    out = bytearray()
    out.extend(source[:inject_start])
    if field_bytes:
        out.extend(field_bytes)
    out.extend(source[inject_end:])

    result = bytes(out)
    if len(result) > write_len:
        return hookapi.TOO_SMALL

    rt._write_memory(write_ptr, result)
    return len(result)


def sto_erase(
    rt: HookRuntime,
    write_ptr: int,
    write_len: int,
    read_ptr: int,
    read_len: int,
    field_id: int,
) -> int:
    """Remove a field from a serialized object.

    Delegates to sto_emplace with fread_ptr=0, fread_len=0 (delete mode).
    If the result length equals the input length, the field was not found.
    """
    ret = sto_emplace(rt, write_ptr, write_len, read_ptr, read_len, 0, 0, field_id)
    if ret > 0 and ret == read_len:
        return hookapi.DOESNT_EXIST
    return ret


def sto_validate(rt: HookRuntime, read_ptr: int, read_len: int) -> int:
    """Validate that bytes are a well-formed serialized object.

    Returns 1 if valid, 0 if not.
    """
    if read_len < 2:
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)

    try:
        consumed = 0
        for _fid, _tc, _fc, offset, total_len, _po, _pl in _walk_fields(data):
            consumed = offset + total_len
        return 1 if consumed == len(data) else 0
    except Exception:
        return 0
