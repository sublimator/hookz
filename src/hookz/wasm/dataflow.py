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


# ---------------------------------------------------------------------------
# Stack effects
# ---------------------------------------------------------------------------
#
# (pops, pushes) per opcode. Only what a hook can contain, and anything absent
# is a refusal rather than a guess: mis-modelling one arity slides the stack
# under every later instruction, and the call whose arguments are then read off
# it gets a confident wrong answer. `UnmodelledOpcode` says so instead.

_UNARY = (1, 1)
_BINARY = (2, 1)

_EFFECTS: dict[int, tuple[int, int]] = {
    0x0F: (0, 0),                       # return — handled as a barrier
    0x1A: (1, 0),                       # drop
    0x1B: (3, 1),                       # select
    0x20: (0, 1), 0x21: (1, 0), 0x22: (1, 1),   # local get/set/tee
    0x23: (0, 1), 0x24: (1, 0),                 # global get/set
    0x41: (0, 1), 0x42: (0, 1), 0x43: (0, 1), 0x44: (0, 1),   # consts
    0xA7: _UNARY, 0xAC: _UNARY, 0xAD: _UNARY,   # wrap / extend
}

# loads: one address in, one value out
for _op in range(0x28, 0x36):
    _EFFECTS[_op] = _UNARY
# stores: address and value in, nothing out
for _op in range(0x36, 0x3F):
    _EFFECTS[_op] = (2, 0)
# i32.eqz / i64.eqz are the only unary tests
_EFFECTS[0x45] = _UNARY
_EFFECTS[0x50] = _UNARY
# every other numeric op in these ranges is binary
for _op in list(range(0x46, 0x50)) + list(range(0x51, 0x5B)):
    _EFFECTS[_op] = _BINARY
for _op in range(0x6A, 0x79):           # i32 arithmetic
    _EFFECTS[_op] = _BINARY
for _op in range(0x7C, 0x8B):           # i64 arithmetic
    _EFFECTS[_op] = _BINARY
for _op in (0x67, 0x68, 0x69, 0x79, 0x7A, 0x7B):   # clz/ctz/popcnt
    _EFFECTS[_op] = _UNARY
del _op

# Control flow. The stack model is abandoned at each of these rather than
# merged: joining two branches needs a lattice, and claiming to know a value
# that depends on which way a branch went is the error worth never making.
BARRIERS = frozenset({0x02, 0x03, 0x04, 0x05, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                      0x00, 0x11})


class UnmodelledOpcode(Exception):
    """An opcode whose stack effect is not in the table."""


@dataclass(frozen=True)
class Const:
    """A literal, which is what a field id or a buffer address looks like."""
    value: int


@dataclass(frozen=True)
class Local:
    index: int


@dataclass(frozen=True)
class Computed:
    """A value derived from others. Kept as a shape, not evaluated."""
    opcode: int


@dataclass(frozen=True)
class Unknown:
    """The model could not say. Never conflated with a value."""
    why: str


@dataclass(frozen=True)
class CallSite:
    offset: int
    func_index: int
    args: tuple


def _arity(module, func_index: int) -> tuple[int, int]:
    """(params, results) of a function, imported or defined."""
    n_imports = len(module.imports)
    if func_index < n_imports:
        type_idx = module.imports[func_index].type_idx
    else:
        type_idx = module.functions[func_index - n_imports]
    ft = module.types[type_idx]
    return len(ft.params), len(ft.results)


def call_sites(wasm: bytes, module=None) -> list[CallSite]:
    """Every `call`, with the arguments recoverable at it.

    Simulated forward within a basic block. At a control-flow instruction the
    stack model is abandoned, so an argument pushed before a branch reads as
    `Unknown` rather than as whatever happened to be modelled. Conservative on
    purpose — the question this answers is "which constant is passed here",
    and a wrong constant is worse than no constant.
    """
    from .decode import decode_code_bodies_raw, decode_module

    if module is None:
        module = decode_module(wasm)

    out: list[CallSite] = []
    for start, end in decode_code_bodies_raw(wasm):
        stack: list = []
        for instr in decode_body(wasm, start, end):
            op = instr.opcode

            if op == OP_CALL:
                params, results = _arity(module, instr.imm[0])
                if len(stack) >= params:
                    args = tuple(stack[len(stack) - params:]) if params else ()
                    del stack[len(stack) - params:]
                else:
                    args = tuple([Unknown("before a branch")] * (params - len(stack))
                                 + stack)
                    stack.clear()
                out.append(CallSite(instr.offset, instr.imm[0], args))
                stack.extend(Computed(op) for _ in range(results))
                continue

            if op in BARRIERS:
                stack.clear()
                continue

            effect = _EFFECTS.get(op)
            if effect is None:
                if op == OP_CALL_INDIRECT:
                    stack.clear()
                    continue
                raise UnmodelledOpcode(
                    f"opcode 0x{op:02X} at {instr.offset} has no stack effect "
                    "in the table; add it rather than letting the model drift")
            pops, pushes = effect
            if len(stack) < pops:
                stack.clear()
            else:
                del stack[len(stack) - pops:]

            if pushes:
                if op in (OP_I32_CONST, OP_I64_CONST):
                    stack.append(Const(instr.imm[0]))
                elif op in (OP_GET_LOCAL, OP_TEE_LOCAL):
                    stack.append(Local(instr.imm[0]))
                else:
                    stack.extend(Computed(op) for _ in range(pushes))
    return out


def call_sites_over(body: bytes) -> list[CallSite]:
    """`call_sites` for a bare instruction sequence, for tests and probes."""
    class _Empty:
        imports: list = []
        functions: list = []
        types: list = []

    out: list[CallSite] = []
    stack: list = []
    for instr in decode_body(body, 0, len(body)):
        op = instr.opcode
        if op in BARRIERS:
            stack.clear()
            continue
        effect = _EFFECTS.get(op)
        if effect is None:
            raise UnmodelledOpcode(
                f"opcode 0x{op:02X} at {instr.offset} has no stack effect "
                "in the table; add it rather than letting the model drift")
        pops, pushes = effect
        del stack[max(0, len(stack) - pops):]
        stack.extend(Computed(op) for _ in range(pushes))
    return out
