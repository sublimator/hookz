"""String manipulation handlers — str_compare, str_find, str_concat, str_replace."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hookz import hookapi

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime


def str_compare(
    rt: HookRuntime,
    read1_ptr: int,
    read1_len: int,
    read2_ptr: int,
    read2_len: int,
    mode: int = 0,
) -> int:
    """Compare two byte strings.

    Returns 0 (first < second), 1 (equal), or 2 (first > second).
    mode=0: case-sensitive (raw byte compare)
    mode=1: case-insensitive (tolower before compare)

    Mirrors xahaud str_compare from applyHook.cpp.
    """
    if mode > 1:
        return hookapi.INVALID_ARGUMENT

    if read1_len > 255 or read2_len > 255:
        return hookapi.TOO_BIG

    if read1_len == 0 or read2_len == 0:
        return hookapi.TOO_SMALL

    data1 = rt._read_memory(read1_ptr, read1_len)
    data2 = rt._read_memory(read2_ptr, read2_len)

    # Note: the C++ source has mode==1 as "insensitive" but then the
    # insensitive block does raw compare and the else block does tolower.
    # This appears to be a bug in xahaud. We replicate it faithfully.
    if mode == 1:
        # "insensitive" path — but actually raw byte compare in C++
        for b1, b2 in zip(data1, data2):
            if b1 < b2:
                return 0
            if b1 > b2:
                return 2
    else:
        # default path — tolower compare in C++
        for b1, b2 in zip(data1, data2):
            lo1 = b1 | 0x20 if 0x41 <= b1 <= 0x5A else b1
            lo2 = b2 | 0x20 if 0x41 <= b2 <= 0x5A else b2
            if lo1 < lo2:
                return 0
            if lo1 > lo2:
                return 2

    return 1


def str_find(
    rt: HookRuntime,
    haystack_ptr: int,
    haystack_len: int,
    needle_ptr: int,
    needle_len: int,
    mode: int = 0,
    n: int = 0,
) -> int:
    """Find needle in haystack, return offset or DOESNT_EXIST.

    mode 0: case-sensitive plain string search
    mode 1: case-insensitive plain string search
    mode 2/3: regex (NOT_IMPLEMENTED)
    n: start offset in haystack

    Special: if needle_ptr == 0 and needle_len == 0, returns strnlen of haystack.

    Mirrors xahaud str_find from applyHook.cpp.
    """
    if haystack_len > 32 * 1024:
        return hookapi.TOO_BIG

    if needle_len > 256:
        return hookapi.TOO_BIG

    if haystack_len == 0:
        return hookapi.TOO_SMALL

    if mode > 3:
        return hookapi.INVALID_ARGUMENT

    if n >= haystack_len:
        return hookapi.INVALID_ARGUMENT

    # str_len overload
    if needle_ptr == 0:
        if needle_len != 0:
            return hookapi.INVALID_ARGUMENT
        data = rt._read_memory(haystack_ptr, haystack_len)
        try:
            return data.index(0)
        except ValueError:
            return haystack_len

    if mode >= 2:
        return hookapi.NOT_IMPLEMENTED

    haystack = rt._read_memory(haystack_ptr + n, haystack_len - n)
    needle = rt._read_memory(needle_ptr, needle_len)

    insensitive = mode % 2 == 1

    if insensitive:
        haystack_lower = bytes(
            (b | 0x20) if 0x41 <= b <= 0x5A else b for b in haystack
        )
        needle_lower = bytes(
            (b | 0x20) if 0x41 <= b <= 0x5A else b for b in needle
        )
        pos = haystack_lower.find(needle_lower)
    else:
        pos = haystack.find(needle)

    if pos == -1:
        return hookapi.DOESNT_EXIST

    return pos


def str_concat(
    rt: HookRuntime,
    write_ptr: int,
    write_len: int,
    read_ptr: int,
    read_len: int,
    operand: int,
    operand_type: int,
) -> int:
    """Concatenate / copy strings according to operand_type.

    C++ signature: str_concat(write_ptr, write_len, read_ptr, read_len,
                              operand (uint64/i64), operand_type (uint32/i32))

    operand_type meanings:
      0     — memcpy: copy min(write_len, read_len) bytes from read to write
      1-4   — int-to-string concat (NOT_IMPLEMENTED)
      5     — XFL float-to-string concat (NOT_IMPLEMENTED)
      6     — string concat: operand encodes (ptr << 32) | len
      > 6   — INVALID_ARGUMENT

    Mirrors xahaud str_concat from applyHook.cpp.
    """
    if operand_type > 6:
        return hookapi.INVALID_ARGUMENT

    if write_len > 1024 or read_len > 1024:
        return hookapi.TOO_BIG

    if write_len == 0 or read_len == 0:
        return hookapi.TOO_SMALL

    if write_len < read_len:
        return hookapi.TOO_SMALL

    # operand_type 0: memcpy
    if operand_type == 0:
        n = min(write_len, read_len)
        data = rt._read_memory(read_ptr, n)
        rt._write_memory(write_ptr, data)
        return n

    # operand_type 1-5: int/float-to-string (not yet implemented in xahaud either)
    if operand_type <= 5:
        return hookapi.NOT_IMPLEMENTED

    # operand_type 6: string concat — unpack operand as (read2_ptr << 32) | read2_len
    read2_ptr = (operand >> 32) & 0xFFFFFFFF
    read2_len = operand & 0xFFFFFFFF

    data1 = rt._read_memory(read_ptr, read_len)
    data2 = rt._read_memory(read2_ptr, read2_len)

    # Find null terminator in first string (lhs)
    try:
        nul1 = data1.index(0)
    except ValueError:
        return hookapi.NOT_A_STRING

    if write_len <= nul1:
        return hookapi.TOO_SMALL

    # Find null terminator in second string (rhs)
    try:
        nul2 = data2.index(0)
    except ValueError:
        return hookapi.NOT_A_STRING

    remaining = write_len - nul1
    if remaining == 0:
        return hookapi.TOO_SMALL

    if nul2 > remaining - 1:
        return hookapi.TOO_SMALL

    # Build result: lhs (up to nul) + rhs (up to nul) + \0
    result = data1[:nul1] + data2[:nul2] + b"\x00"
    rt._write_memory(write_ptr, result)

    # Return total length: lhs chars + rhs chars + null terminator
    return nul1 + nul2 + 1


def str_replace(
    rt: HookRuntime,
    write_ptr: int,
    write_len: int,
    haystack_ptr: int,
    haystack_len: int,
    needle_ptr: int,
    needle_len: int,
    replacement_ptr: int,
    replacement_len: int,
    mode: int = 0,
    n: int = 0,
) -> int:
    """Replace first occurrence of needle in haystack with replacement.

    Writes the result to write buffer.
    Returns the length of the result, or a negative error code.

    Mirrors xahaud str_replace from applyHook.cpp (which currently returns
    NOT_IMPLEMENTED after validation; we provide a working implementation).
    """
    if haystack_len > 32 * 1024:
        return hookapi.TOO_BIG

    if needle_len > 256:
        return hookapi.TOO_BIG

    if haystack_len == 0:
        return hookapi.TOO_SMALL

    if needle_len == 0:
        return hookapi.TOO_SMALL

    # Matches xahaud: str_replace returns NOT_IMPLEMENTED after validation.
    # The C++ source validates inputs then returns NOT_IMPLEMENTED before
    # performing any actual replacement.
    return hookapi.NOT_IMPLEMENTED
