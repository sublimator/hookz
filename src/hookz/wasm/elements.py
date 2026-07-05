"""Element section rewriting — shift function indices.

Used by the coverage rewriter after prepending an import, which shifts
every function index by one. Only the const-expression grammar the WASM
spec allows inside element segments is understood; anything else raises
rather than risking silent corruption.
"""

from __future__ import annotations

from .leb128 import read_signed, read_unsigned, write_signed, write_unsigned


class ElementRewriteError(Exception):
    """Raised when an element segment uses an unsupported encoding."""


def _copy_const_expr(data: bytes, pos: int, out: bytearray, shift: int) -> int:
    """Copy a const expression, shifting ref.func indices. Returns new pos."""
    while pos < len(data):
        op = data[pos]
        out.append(op)
        pos += 1
        if op == 0x0B:  # end
            return pos
        if op in (0x41, 0x42):  # i32.const / i64.const
            v, pos = read_signed(data, pos)
            out.extend(write_signed(v))
        elif op == 0x43:  # f32.const
            out.extend(data[pos:pos + 4])
            pos += 4
        elif op == 0x44:  # f64.const
            out.extend(data[pos:pos + 8])
            pos += 8
        elif op == 0x23:  # global.get
            v, pos = read_unsigned(data, pos)
            out.extend(write_unsigned(v))
        elif op == 0xD0:  # ref.null: heap type byte
            out.append(data[pos])
            pos += 1
        elif op == 0xD2:  # ref.func — the index that must shift
            v, pos = read_unsigned(data, pos)
            out.extend(write_unsigned(v + shift))
        else:
            raise ElementRewriteError(
                f"Unsupported opcode 0x{op:02X} in element const expression")
    raise ElementRewriteError("Unterminated const expression in element segment")


def _copy_funcidx_vec(data: bytes, pos: int, out: bytearray, shift: int) -> int:
    """Copy a vec(funcidx), shifting every index. Returns new pos."""
    n, pos = read_unsigned(data, pos)
    out.extend(write_unsigned(n))
    for _ in range(n):
        v, pos = read_unsigned(data, pos)
        out.extend(write_unsigned(v + shift))
    return pos


def _copy_expr_vec(data: bytes, pos: int, out: bytearray, shift: int) -> int:
    """Copy a vec(expr), shifting ref.func indices. Returns new pos."""
    n, pos = read_unsigned(data, pos)
    out.extend(write_unsigned(n))
    for _ in range(n):
        pos = _copy_const_expr(data, pos, out, shift)
    return pos


def shift_element_func_indices(section_data: bytes, shift: int) -> bytes:
    """Rewrite an element section's function indices by +shift.

    Handles all segment encodings (flags 0-7). Raises ElementRewriteError
    on anything it doesn't understand.
    """
    data = section_data
    out = bytearray()
    count, pos = read_unsigned(data, 0)
    out.extend(write_unsigned(count))

    for _ in range(count):
        flags, pos = read_unsigned(data, pos)
        out.extend(write_unsigned(flags))

        if flags == 0:  # active, table 0: expr, vec(funcidx)
            pos = _copy_const_expr(data, pos, out, shift)
            pos = _copy_funcidx_vec(data, pos, out, shift)
        elif flags in (1, 3):  # passive/declared: elemkind, vec(funcidx)
            out.append(data[pos])
            pos += 1
            pos = _copy_funcidx_vec(data, pos, out, shift)
        elif flags == 2:  # active: tableidx, expr, elemkind, vec(funcidx)
            t, pos = read_unsigned(data, pos)
            out.extend(write_unsigned(t))
            pos = _copy_const_expr(data, pos, out, shift)
            out.append(data[pos])
            pos += 1
            pos = _copy_funcidx_vec(data, pos, out, shift)
        elif flags == 4:  # active, table 0: expr, vec(expr)
            pos = _copy_const_expr(data, pos, out, shift)
            pos = _copy_expr_vec(data, pos, out, shift)
        elif flags in (5, 7):  # passive/declared: reftype, vec(expr)
            out.append(data[pos])
            pos += 1
            pos = _copy_expr_vec(data, pos, out, shift)
        elif flags == 6:  # active: tableidx, expr, reftype, vec(expr)
            t, pos = read_unsigned(data, pos)
            out.extend(write_unsigned(t))
            pos = _copy_const_expr(data, pos, out, shift)
            out.append(data[pos])
            pos += 1
            pos = _copy_expr_vec(data, pos, out, shift)
        else:
            raise ElementRewriteError(f"Unsupported element segment flags {flags}")

    if pos != len(data):
        raise ElementRewriteError("Trailing bytes in element section")
    return bytes(out)
