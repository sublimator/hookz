"""Instruction-level decoding, for asking what a hook does with its data.

`guard.py` walks the same bytes to answer a structural question — how deeply
are blocks nested, is every loop guarded — and to do that it only has to get
*past* each instruction, so `_skip_operands` reads the immediates and throws
them away. The values are the whole point here, so this decodes them.

What that buys, over reading the C: a call site's arguments are recoverable
even when the source hid them behind a macro, a `#define`d offset, or an
expression the C tools decline to evaluate. `state_set(SBUF(v), SBUF(k))`
says nothing about which key; the binary says the pointer is a constant
address, and the data section says what is at it.

The decoder is deliberately total. Every opcode a hook may contain has to
advance the cursor by exactly the right amount, because being one byte out
does not raise — it resynchronises on a byte that was an immediate and
silently reports a different program. `decode_body` therefore checks it landed
exactly on the end of the body, which is the only cheap proof that the walk
was in step the whole way.
"""

from __future__ import annotations

from dataclasses import dataclass

from wasm_tob import (
    OP_BLOCK, OP_BR, OP_BR_IF, OP_BR_TABLE, OP_CALL, OP_CALL_INDIRECT,
    OP_CURRENT_MEMORY, OP_F32_CONST, OP_F64_CONST,
    OP_GET_GLOBAL, OP_GET_LOCAL, OP_GROW_MEMORY, OP_I32_CONST, OP_I64_CONST,
    OP_IF, OP_LOOP, OP_SET_GLOBAL, OP_SET_LOCAL,
    OP_TEE_LOCAL,
)

from .leb128 import read_signed, read_unsigned

# Mirrors guard.py, which takes these from wasm_tob's tables.
MEMOP_FIRST, MEMOP_LAST = 0x28, 0x3E
NUMOP_FIRST, NUMOP_LAST = 0x45, 0xC4

OP_SELECT_T = 0x1C
OP_TABLE_GET = 0x25
OP_TABLE_SET = 0x26
OP_REF_NULL = 0xD0
OP_REF_IS_NULL = 0xD1
OP_REF_FUNC = 0xD2
OP_PREFIX_FC = 0xFC
OP_PREFIX_FD = 0xFD

BLOCK_TYPE_BYTES = frozenset({0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F, 0x40})

_LOCAL_OPS = frozenset({OP_GET_LOCAL, OP_SET_LOCAL, OP_TEE_LOCAL})
_GLOBAL_OPS = frozenset({OP_GET_GLOBAL, OP_SET_GLOBAL})


class DecodeDesync(Exception):
    """The walk did not land on the end of the body.

    Raised rather than returned because every instruction after the slip
    describes a program that was never in the file.
    """


@dataclass(frozen=True)
class Instr:
    """One instruction, with its immediates decoded.

    `imm` holds them in the order they appear: `(local_index,)` for a local
    op, `(value,)` for a const, `(align, offset)` for a memory op,
    `(func_index,)` for a call. Empty for the arithmetic that only consumes
    the stack.
    """
    offset: int          # byte offset into the module
    opcode: int
    imm: tuple = ()

    @property
    def is_call(self) -> bool:
        return self.opcode == OP_CALL

    @property
    def is_const(self) -> bool:
        return self.opcode in (OP_I32_CONST, OP_I64_CONST)

    @property
    def is_local(self) -> bool:
        return self.opcode in _LOCAL_OPS

    @property
    def is_memory(self) -> bool:
        return MEMOP_FIRST <= self.opcode <= MEMOP_LAST


def _immediates(wasm: bytes, opcode: int, i: int) -> tuple[tuple, int]:
    """The immediates of one instruction, and the offset just past them.

    Shapes follow `guard._skip_operands`; the difference is that the values
    are kept. Where the two disagree about a width, the module stops decoding
    at the wrong byte, which `decode_body` turns into a `DecodeDesync` rather
    than a wrong answer.
    """
    if opcode in (OP_BR, OP_BR_IF):
        v, i = read_unsigned(wasm, i)
        return (v,), i
    if opcode == OP_BR_TABLE:
        count, i = read_unsigned(wasm, i)
        targets = []
        for _ in range(count):
            v, i = read_unsigned(wasm, i)
            targets.append(v)
        default, i = read_unsigned(wasm, i)
        return (tuple(targets), default), i
    if opcode == OP_CALL:
        v, i = read_unsigned(wasm, i)
        return (v,), i
    if opcode == OP_CALL_INDIRECT:
        type_idx, i = read_unsigned(wasm, i)
        table_idx, i = read_unsigned(wasm, i)
        return (type_idx, table_idx), i
    if opcode == OP_REF_NULL:
        return (wasm[i],), i + 1
    if opcode == OP_REF_FUNC:
        v, i = read_unsigned(wasm, i)
        return (v,), i
    if opcode == OP_SELECT_T:
        count, i = read_unsigned(wasm, i)
        return (tuple(wasm[i:i + count]),), i + count
    if opcode in _LOCAL_OPS or opcode in _GLOBAL_OPS:
        v, i = read_unsigned(wasm, i)
        return (v,), i
    if opcode in (OP_TABLE_GET, OP_TABLE_SET):
        v, i = read_unsigned(wasm, i)
        return (v,), i
    if MEMOP_FIRST <= opcode <= MEMOP_LAST:
        align, i = read_unsigned(wasm, i)
        offset, i = read_unsigned(wasm, i)
        return (align, offset), i
    if opcode in (OP_CURRENT_MEMORY, OP_GROW_MEMORY):
        return (wasm[i],), i + 1
    if opcode in (OP_I32_CONST, OP_I64_CONST):
        v, i = read_signed(wasm, i)
        return (v,), i
    if opcode == OP_F32_CONST:
        return (wasm[i:i + 4],), i + 4
    if opcode == OP_F64_CONST:
        return (wasm[i:i + 8],), i + 8
    if opcode == OP_PREFIX_FC:
        fc, i = read_unsigned(wasm, i)
        if 12 <= fc <= 17:
            _, i = read_unsigned(wasm, i)
            if fc in (12, 14):
                _, i = read_unsigned(wasm, i)
        elif fc == 8:
            _, i = read_unsigned(wasm, i)
            i += 1
        elif fc == 9:
            _, i = read_unsigned(wasm, i)
        elif fc == 10:
            i += 2
        elif fc == 11:
            i += 1
        return (fc,), i
    if opcode == OP_PREFIX_FD:
        v, i = read_unsigned(wasm, i)
        if v <= 11:
            _, i = read_unsigned(wasm, i)
            _, i = read_unsigned(wasm, i)
        elif 84 <= v <= 91:
            _, i = read_unsigned(wasm, i)
            _, i = read_unsigned(wasm, i)
            i += 1
        elif 21 <= v <= 34:
            i += 1
        elif v in (12, 13):
            i += 16
        return (v,), i
    if opcode in (OP_BLOCK, OP_LOOP, OP_IF):
        if wasm[i] in BLOCK_TYPE_BYTES:
            return (wasm[i],), i + 1
        v, i = read_signed(wasm, i)
        return (v,), i
    # unreachable/nop/else/end/return/drop/select and the numeric ops take none
    return (), i


def decode_body(wasm: bytes, start: int, end: int) -> list[Instr]:
    """Every instruction in `[start, end)`, immediates decoded.

    Raises `DecodeDesync` unless the walk consumes the body exactly. A decoder
    that is one byte out keeps producing plausible instructions, so landing on
    the boundary is the cheap end-to-end check that it never was.
    """
    out: list[Instr] = []
    i = start
    while i < end:
        offset = i
        opcode = wasm[i]
        imm, i = _immediates(wasm, opcode, i + 1)
        out.append(Instr(offset=offset, opcode=opcode, imm=imm))
    if i != end:
        raise DecodeDesync(
            f"decoding ran to {i}, body ends at {end} — the walk lost sync "
            f"and every instruction after that point is fiction")
    return out
