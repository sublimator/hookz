"""STO (Serialized Transaction Object) handlers — subfield, subarray, emplace, erase, validate.

The host does not parse these with STObject. It walks the buffer with its own
light-weight measurer, `get_stobject_length`
(xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3124), which knows serialized
*types* but not fields, and whose answers depend on the amendments in force.
`_get_stobject_length` below is a port of it; the handlers port the loops
around it:

  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:72    (sto_validate)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:108   (sto_subfield)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:176   (sto_subarray)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:266   (sto_emplace)

Amendments that change the answers:

- fix20260929 — sto_subfield, sto_subarray and sto_emplace validate the whole
  source first; a wrapped array must end in F1; an injected field must parse
  to exactly its buffer; and the measurer refuses a length running past the
  buffer instead of reporting it.
- fixHookAPI20251128 — sto_subarray unwraps a two-byte (F0 xx) array header;
  sto_emplace refuses an injected field that does not parse, or is not
  `field_id`.
- featureHookAPISerializedType240 — types up to STI_CURRENCY (26) are
  measured, and STI_PATHSET is parsed rather than read as a VL.

Without fix20260929 the host's measurer can read past the buffer (PATHSET,
ISSUE, XCHAIN_BRIDGE, all Type240-only). Those bytes are heap, which hookz
cannot reproduce; such a read is reported as a parse failure, which is what
the fix answers for every one of them.

`_walk_fields` is not the host's parser. It is xrpl-py's BinaryParser, kept
for the slot and transaction code that parse real STObjects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hookz import hookapi
from hookz.xrpl.xrpl_patch import patch_xahau_definitions

if TYPE_CHECKING:
    from collections.abc import Container

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


# SerializedTypeID, as include/xrpl/protocol/SField.h numbers it — the codes
# get_stobject_length switches on.
_STI_UINT16 = 1
_STI_UINT32 = 2
_STI_UINT64 = 3
_STI_UINT128 = 4
_STI_UINT256 = 5
_STI_AMOUNT = 6
_STI_VL = 7
_STI_ACCOUNT = 8
_STI_NUMBER = 9
_STI_OBJECT = 14
_STI_ARRAY = 15
_STI_UINT8 = 16
_STI_UINT160 = 17
_STI_PATHSET = 18
_STI_VECTOR256 = 19
_STI_UINT96 = 20
_STI_UINT192 = 21
_STI_UINT384 = 22
_STI_UINT512 = 23
_STI_ISSUE = 24
_STI_XCHAIN_BRIDGE = 25
_STI_CURRENCY = 26

_FIXED_WIDTH = {
    _STI_UINT16: 2, _STI_UINT32: 4, _STI_UINT64: 8, _STI_UINT128: 16,
    _STI_UINT256: 32, _STI_UINT8: 1, _STI_UINT160: 20, _STI_CURRENCY: 20,
}

_ZERO20 = bytes(20)


class _ParseError(Exception):
    """get_stobject_length returned an STOParseErrorCode. Which one is never
    visible to a hook — every caller turns it into PARSE_ERROR or 0."""


def _get_stobject_length(data: bytes, start: int, end: int,
                         rules: Container[str], depth: int = 0
                         ) -> tuple[int, int, int, int, int]:
    """Port of HookAPI::get_stobject_length.

    Measures the field at `data[start]`, bounded by `end` (which may be short
    of `len(data)`: sto_subarray drops the array's closing F1). Returns
    `(length, type, field, payload_start, payload_length)` — length counts
    the header, and the footer of an object or array; payload_start is
    relative to `start`. Raises _ParseError where the host returns an error.
    """
    def at(i: int) -> int:
        # The host reads `*ptr` without a bound wherever the C++ below does;
        # inside the copied buffer that is a real byte, past it is not.
        if i >= len(data):
            raise _ParseError("read past the buffer")
        return data[i]

    fix = "fix20260929" in rules
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3137
    if depth > 10:
        raise _ParseError("excessive nesting")

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3140
    max_sti_type = (_STI_CURRENCY if "featureHookAPISerializedType240" in rules
                    else _STI_VECTOR256)

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3149-3180 — the header
    upto = start
    high = at(upto) >> 4
    low = at(upto) & 0xF
    upto += 1
    if upto >= end:
        raise _ParseError("unexpected end")
    if high > 0 and low > 0:
        type_, field = high, low
    elif high > 0:
        type_, field = high, at(upto)
        upto += 1
    elif low > 0:
        field, type_ = low, at(upto)
        upto += 1
    else:
        type_ = at(upto)
        upto += 1
        if upto >= end:
            raise _ParseError("unexpected end")
        field = at(upto)
        upto += 1

    if upto >= end:
        raise _ParseError("unexpected end")

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3199-3205
    if type_ < 1 or max_sti_type < type_ or 10 <= type_ <= 13:
        raise _ParseError("unknown type")
    if type_ in (_STI_NUMBER, _STI_UINT96, _STI_UINT192, _STI_UINT384, _STI_UINT512):
        raise _ParseError("unsupported type")

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3207
    is_vl = (type_ in (_STI_ACCOUNT, _STI_VL, _STI_VECTOR256)
             or (type_ == _STI_PATHSET
                 and "featureHookAPISerializedType240" not in rules))

    length = -1
    if is_vl:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3214-3243
        length = at(upto)
        upto += 1
        if upto >= end:
            raise _ParseError("unexpected end")
        if length < 193:
            pass
        elif length < 241:
            length = (length - 193) * 256 + at(upto) + 193
            upto += 1
            if upto > end:
                raise _ParseError("unexpected end")
        else:
            b2 = at(upto)
            upto += 1
            if upto >= end:
                raise _ParseError("unexpected end")
            length = (length - 241) * 65536 + 12481 + b2 * 256 + at(upto)
            upto += 1
            if upto >= end:
                raise _ParseError("unexpected end")
    elif type_ in _FIXED_WIDTH:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3244
        length = _FIXED_WIDTH[type_]
    elif type_ == _STI_AMOUNT:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3278
        length = 8 if at(upto) >> 6 == 1 else 48
    elif type_ == _STI_PATHSET:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3284-3331 (Type240)
        length = 0
        terminated = False
        while upto + length < end:
            while at(upto + length) & 0x31:
                flag = at(upto + length)
                length += 1
                if flag & ~0x31:
                    raise _ParseError("bad path step")
                length += 20 * bool(flag & 0x01) + 20 * bool(flag & 0x10) \
                    + 20 * bool(flag & 0x20)
                # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3306
                if fix and upto + length >= end:
                    raise _ParseError("unexpected end")
                if at(upto + length) in (0x00, 0xFF):
                    break
            lastflag = at(upto + length)
            length += 1
            if lastflag == 0xFF:
                continue
            if lastflag == 0x00:
                terminated = True
                break
            raise _ParseError("bad path terminator")
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3329
        if fix and not terminated:
            raise _ParseError("unterminated paths")
    elif type_ == _STI_ISSUE:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3332-3349
        if fix and end - upto < 20:
            raise _ParseError("unexpected end")
        for i in range(20):
            at(upto + i)
        length = 20 if data[upto:upto + 20] == _ZERO20 else 40
    elif type_ == _STI_XCHAIN_BRIDGE:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3350-3382
        length = 0
        for _ in range(2):                  # locking chain, issuing chain
            # door account
            if not fix:
                length += 21
            elif end - upto <= length:
                raise _ParseError("unexpected end")
            elif data[upto + length] == 0:
                length += 1
            elif data[upto + length] == 20:
                length += 21
            else:
                raise _ParseError("bad door account")
            # door issue
            if fix and end - upto < length + 20:
                raise _ParseError("unexpected end")
            for i in range(20):
                at(upto + length + i)
            length += 20 if data[upto + length:upto + length + 20] == _ZERO20 else 40

    if length > -1:
        payload_start = upto - start
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3399
        if fix and length > end - upto:
            raise _ParseError("unexpected end")
        return length + (upto - start), type_, field, payload_start, length

    if type_ in (_STI_OBJECT, _STI_ARRAY):
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:3405-3444
        payload_start = upto - start
        for _ in range(1024):
            sublength = _get_stobject_length(data, upto, end, rules, depth + 1)[0]
            upto += sublength
            if upto >= end:
                raise _ParseError("unexpected end")
            if ((data[upto] == 0xE1 and type_ == _STI_OBJECT)
                    or (data[upto] == 0xF1 and type_ == _STI_ARRAY)):
                payload_length = upto - start - payload_start
                upto += 1
                return upto - start, type_, field, payload_start, payload_length
        raise _ParseError("excessive size")

    raise _ParseError("unknown type")


def _measure(data: bytes, upto: int, end: int, rules: Container[str]):
    """One get_stobject_length call, or None where the host's Expected is
    empty."""
    try:
        return _get_stobject_length(data, upto, end, rules)
    except _ParseError:
        return None


def _is_valid(data: bytes, rules: Container[str]) -> bool:
    """HookAPI::sto_validate for a buffer of two bytes or more
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:87-104)."""
    upto, end = 0, len(data)
    for _ in range(1024):
        if upto >= end:
            break
        m = _measure(data, upto, end, rules)
        if m is None:
            return False
        upto += m[0]
    return upto == end


def _pack(offset: int, length: int) -> int:
    """The wrapper's `(uint64_t(first) << 32) + (uint32_t)second`."""
    return ((offset & 0xFFFFFFFF) << 32) + (length & 0xFFFFFFFF)


def sto_subfield(rt: HookRuntime, read_ptr: int, read_len: int, field_id: int) -> int:
    """Find a field in a serialized object, return packed (offset << 32 | length).

    Arrays are returned whole, header included; every other field as its
    payload. xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:108-172. Under
    fix20260929 the whole buffer must validate first, so a field after the
    one asked for can make the answer PARSE_ERROR (:113-119).
    """
    rules = rt.amendments
    field_id &= 0xFFFFFFFF
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:110
    if read_len < 2:
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:113
    if "fix20260929" in rules and not _is_valid(data, rules):
        return hookapi.PARSE_ERROR

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:136
    upto, end = 0, len(data)
    for _ in range(1024):
        if upto >= end:
            break
        m = _measure(data, upto, end, rules)
        if m is None:
            return hookapi.PARSE_ERROR
        length, type_, field, payload_start, payload_length = m
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:150
        if (type_ << 16) + field == field_id:
            if type_ == _STI_ARRAY:
                return _pack(upto, length)
            return _pack(upto + payload_start, payload_length)
        upto += length

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:169
    if upto != end:
        return hookapi.PARSE_ERROR
    return hookapi.DOESNT_EXIST


def sto_subarray(rt: HookRuntime, read_ptr: int, read_len: int, index: int) -> int:
    """Find element at index in a serialized array, return packed (offset << 32 | length).

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:176-262. A wrapped array
    (first byte Fx) is unwrapped by one header byte and the closing byte —
    two header bytes for F0 xx under fixHookAPI20251128 (:205). Under
    fix20260929 a wrapped array must end in F1, and the whole buffer must
    validate, before any element is found (:185-196).
    """
    rules = rt.amendments
    index &= 0xFFFFFFFF
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:178
    if read_len < 2:
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)
    upto, end = 0, len(data)

    if "fix20260929" in rules:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:188
        if data[0] & 0xF0 == 0xF0 and data[end - 1] != 0xF1:
            return hookapi.PARSE_ERROR
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:192
        if not _is_valid(data, rules):
            return hookapi.PARSE_ERROR

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:203-219
    if data[0] & 0xF0 == 0xF0:
        if "fixHookAPI20251128" in rules and data[0] == 0xF0:
            upto += 2                       # field code > 15: F0 xx
        else:
            upto += 1
        end -= 1                            # the closing F1

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:221
    if upto >= end:
        return hookapi.PARSE_ERROR

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:230
    for i in range(1024):
        if upto >= end:
            break
        m = _measure(data, upto, end, rules)
        if m is None:
            return hookapi.PARSE_ERROR
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:245
        if i == index:
            return _pack(upto, m[0])
        upto += m[0]

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:259
    if upto != end:
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

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:266-415. Before the scan:
    under fix20260929 the source must validate (:291-296); under
    fixHookAPI20251128 the injected field must parse and be `field_id`
    (:298-325), and under fix20260929 as well it must parse to exactly its
    buffer (:318-320) — without that a trailing byte rides along.
    """
    rules = rt.amendments
    field_id &= 0xFFFFFFFF
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

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:291
    if "fix20260929" in rules and not _is_valid(source, rules):
        return hookapi.PARSE_ERROR

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:298
    if field_bytes is not None and "fixHookAPI20251128" in rules:
        m = _measure(field_bytes, 0, len(field_bytes), rules)
        if m is None:
            return hookapi.PARSE_ERROR
        length, type_, field, _ps, _pl = m
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:318
        if "fix20260929" in rules and length != len(field_bytes):
            return hookapi.PARSE_ERROR
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:321
        if (type_ << 16) + field != field_id:
            return hookapi.PARSE_ERROR

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:338-376 — find the
    # canonical injection point
    upto, end = 0, len(source)
    inject_start = inject_end = end
    for _ in range(1024):
        if upto >= end:
            break
        m = _measure(source, upto, end, rules)
        if m is None:
            return hookapi.PARSE_ERROR
        length, type_, field = m[0], m[1], m[2]
        fid = (type_ << 16) + field
        if fid == field_id:
            inject_start, inject_end = upto, upto + length
            break
        if fid > field_id:
            inject_start = inject_end = upto
            break
        upto += length

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:381
    if upto > end:
        return hookapi.PARSE_ERROR

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:388-411 — a matched field
    # that runs past the source (possible only without fix20260929) leaves
    # no tail to copy
    out = bytearray(source[:inject_start])
    if field_bytes:
        out.extend(field_bytes)
    if end - inject_end > 0:
        out.extend(source[inject_end:end])

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

    A buffer under two bytes is reported as invalid (0) under fix20261005,
    and as TOO_SMALL without it
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:74-81).
    """
    if read_len < 2:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:78
        if "fix20261005" in rt.amendments:
            return 0
        return hookapi.TOO_SMALL

    data = rt._read_memory(read_ptr, read_len)
    return 1 if _is_valid(data, rt.amendments) else 0
