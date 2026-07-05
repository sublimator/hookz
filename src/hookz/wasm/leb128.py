"""LEB128 varint encoding — the single implementation shared across hookz.wasm.

Readers take (buffer, offset) and return (value, new_offset); writers take an
int and return bytes. WASM uses these for section lengths, indices, and the
i32/i64 constant immediates.
"""

from __future__ import annotations


class LEB128Error(Exception):
    """Raised when a LEB128 varint is truncated or overflows 64 bits."""


def read_unsigned(buf: bytes, offset: int) -> tuple[int, int]:
    """Parse an unsigned LEB128 varint. Returns (value, new_offset)."""
    val = 0
    shift = 0
    i = offset
    while i < len(buf):
        b = buf[i]
        val |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return val, i
        shift += 7
        if shift >= 64:
            raise LEB128Error("LEB128 overflow")
    raise LEB128Error("LEB128 truncated")


def read_signed(buf: bytes, offset: int) -> tuple[int, int]:
    """Parse a signed LEB128 varint. Returns (value, new_offset)."""
    val = 0
    shift = 0
    i = offset
    while i < len(buf):
        b = buf[i]
        val |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            if shift < 64 and (b & 0x40):
                val |= ~0 << (shift + 7)
            return val, i
        shift += 7
        if shift >= 64:
            raise LEB128Error("LEB128 overflow")
    raise LEB128Error("Signed LEB128 truncated")


def write_unsigned(value: int) -> bytes:
    """Encode a non-negative integer as unsigned LEB128."""
    if value < 0:
        raise LEB128Error(f"Cannot encode negative value {value} as unsigned LEB128")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def write_signed(value: int) -> bytes:
    """Encode an integer as signed LEB128."""
    result = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)
