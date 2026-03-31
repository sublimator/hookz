"""Guard checker — validates WASM hooks have proper _g() guard calls.

Port of xahaud Guard.h validateGuards() + check_guard().
Operates on our internal Module type + raw bytes for instruction walking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from wasm_tob import (
    OP_UNREACHABLE, OP_NOP, OP_BLOCK, OP_LOOP, OP_IF, OP_ELSE, OP_END,
    OP_BR, OP_BR_IF, OP_BR_TABLE, OP_RETURN, OP_CALL, OP_CALL_INDIRECT,
    OP_DROP, OP_SELECT,
    OP_GET_LOCAL, OP_SET_LOCAL, OP_TEE_LOCAL, OP_GET_GLOBAL, OP_SET_GLOBAL,
    OP_I32_CONST, OP_I64_CONST, OP_F32_CONST, OP_F64_CONST,
    OP_CURRENT_MEMORY, OP_GROW_MEMORY,
)

from .types import Module, SectionId
from .decode import decode_module, decode_code_bodies_raw

log = logging.getLogger("hookz.guard")

# Limits from xahaud Enum.h
MAX_GUARD_CALLS = 1024
MAX_WCE = 0xFFFF  # 65535
MAX_NESTING = 16

# WASM opcodes not in wasm-tob constants
OP_SELECT_T = 0x1C
OP_TABLE_GET = 0x25
OP_TABLE_SET = 0x26
OP_REF_NULL = 0xD0
OP_REF_IS_NULL = 0xD1
OP_REF_FUNC = 0xD2
OP_PREFIX_FC = 0xFC
OP_PREFIX_FD = 0xFD

# Block type bytes (value types + void)
BLOCK_TYPE_BYTES = {0x7F, 0x7E, 0x7D, 0x7C, 0x7B, 0x70, 0x6F, 0x40}

# Instruction ranges
MEMOP_FIRST = 0x28  # i32.load
MEMOP_LAST = 0x3E   # i64.store32
NUMOP_FIRST = 0x45  # i32.eqz
NUMOP_LAST = 0xC4   # i64.trunc_sat_f64_u

# Guard rule version bits (from xahaud Enum.h)
GUARD_RULE_FIX_20250131 = 0x01


class GuardError(Exception):
    """Raised when guard validation fails."""

    def __init__(self, message: str, codesec: int = -1, offset: int = -1):
        self.codesec = codesec
        self.offset = offset
        super().__init__(message)


@dataclass
class GuardResult:
    """Result of successful guard validation."""

    hook_wce: int
    cbak_wce: int
    import_count: int
    guard_func_idx: int
    hook_func_idx: int
    cbak_func_idx: int | None


# ---------------------------------------------------------------------------
# LEB128 helpers
# ---------------------------------------------------------------------------

def _leb128(buf: bytes, offset: int) -> tuple[int, int]:
    """Parse unsigned LEB128. Returns (value, new_offset)."""
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
            raise GuardError("LEB128 overflow")
    raise GuardError("LEB128 truncated")


def _signed_leb128(buf: bytes, offset: int) -> tuple[int, int]:
    """Parse signed LEB128. Returns (value, new_offset)."""
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
            raise GuardError("LEB128 overflow")
    raise GuardError("Signed LEB128 truncated")


# ---------------------------------------------------------------------------
# Block tree for worst-case execution computation
# ---------------------------------------------------------------------------

@dataclass
class _BlockInfo:
    iteration_bound: int
    instruction_count: int = 0
    parent: _BlockInfo | None = None
    children: list[_BlockInfo] = field(default_factory=list)
    start_byte: int = 0

    def add_child(self, iteration_bound: int, start_byte: int) -> _BlockInfo:
        child = _BlockInfo(
            iteration_bound=iteration_bound,
            parent=self,
            start_byte=start_byte,
        )
        self.children.append(child)
        return child


def _compute_wce(blk: _BlockInfo, level: int = 0) -> int:
    """Compute worst-case execution count."""
    if level > MAX_NESTING:
        raise GuardError("Maximum block nesting depth reached (16 levels)")
    wce = blk.instruction_count
    for child in blk.children:
        wce += _compute_wce(child, level + 1)
    if blk.parent is None or blk.parent.iteration_bound == 0:
        return wce
    multiplier = blk.iteration_bound / blk.parent.iteration_bound
    return max(int(wce * multiplier), 1)


# ---------------------------------------------------------------------------
# check_guard — validates a single code section's instructions
# ---------------------------------------------------------------------------

def _check_guard(
    wasm: bytes,
    codesec: int,
    start_offset: int,
    end_offset: int,
    guard_func_idx: int,
    last_import_idx: int,
    rules_version: int = 0,
) -> int:
    """Validate guard calls in a code section. Returns worst-case execution count."""
    guard_count = 0
    block_depth = 0
    root = _BlockInfo(iteration_bound=1, start_byte=start_offset)
    current = root

    def _require(pos: int, need: int = 1) -> None:
        if pos + need > len(wasm):
            raise GuardError("Hook truncated", codesec, pos)

    i = start_offset
    while i < end_offset:
        _require(i)
        instr = wasm[i]
        i += 1
        current.instruction_count += 1

        if instr in (OP_UNREACHABLE, OP_NOP, OP_ELSE):
            continue

        if instr in (OP_BLOCK, OP_LOOP, OP_IF):
            _require(i)
            block_type = wasm[i]
            if block_type in BLOCK_TYPE_BYTES:
                i += 1
            else:
                _, i = _signed_leb128(wasm, i)

            iteration_bound = current.iteration_bound if current.parent else 1

            if instr == OP_LOOP:
                _require(i)
                if wasm[i] != OP_I32_CONST:
                    raise GuardError("Missing first i32.const after loop", codesec, i)
                i += 1
                _, i = _signed_leb128(wasm, i)

                _require(i)
                if wasm[i] != OP_I32_CONST:
                    raise GuardError("Missing second i32.const after loop", codesec, i)
                i += 1
                iteration_bound, i = _leb128(wasm, i)

                if iteration_bound == 0:
                    raise GuardError("Guard call cannot specify 0 maxiter", codesec, i)

                _require(i)
                if wasm[i] != OP_CALL:
                    raise GuardError("Missing call to _g after i32.const pair at loop start", codesec, i)
                i += 1
                call_idx, i = _leb128(wasm, i)

                if call_idx != guard_func_idx:
                    raise GuardError(
                        f"Call at loop start was not _g (called {call_idx}, expected {guard_func_idx})",
                        codesec, i)

                guard_count += 1
                if guard_count > MAX_GUARD_CALLS:
                    raise GuardError("Too many guard calls (limit 1024)", codesec, i)

            current = current.add_child(iteration_bound, i)
            block_depth += 1
            continue

        if instr == OP_END:
            block_depth -= 1
            current = current.parent
            if current is None and block_depth == -1 and i >= end_offset:
                break
            if current is None:
                raise GuardError("Illegal block end (no parent)", codesec, i)
            if block_depth < 0:
                raise GuardError("Illegal block end (depth < 0)", codesec, i)
            continue

        if instr in (OP_BR, OP_BR_IF):
            _, i = _leb128(wasm, i)
            continue

        if instr == OP_BR_TABLE:
            vec_count, i = _leb128(wasm, i)
            for _ in range(vec_count):
                _, i = _leb128(wasm, i)
            _, i = _leb128(wasm, i)
            continue

        if instr == OP_RETURN:
            continue

        if instr == OP_CALL:
            callee_idx, i = _leb128(wasm, i)
            if callee_idx > last_import_idx:
                raise GuardError(
                    f"Hook calls function {callee_idx} outside whitelisted imports "
                    f"(last import is {last_import_idx})", codesec, i)
            if callee_idx == guard_func_idx:
                guard_count += 1
                if guard_count > MAX_GUARD_CALLS:
                    raise GuardError("Too many guard calls (limit 1024)", codesec, i)
            continue

        if instr == OP_CALL_INDIRECT:
            raise GuardError("call_indirect is disallowed in hooks", codesec, i)

        if OP_REF_NULL <= instr <= OP_REF_FUNC:
            if instr == OP_REF_NULL:
                _require(i)
                if wasm[i] not in (0x70, 0x6F):
                    raise GuardError("Invalid reftype in ref.null", codesec, i)
                i += 1
            elif instr == OP_REF_FUNC:
                _, i = _leb128(wasm, i)
            continue

        if instr in (OP_DROP, OP_SELECT, OP_SELECT_T):
            if instr == OP_SELECT_T:
                vec_count, i = _leb128(wasm, i)
                i += vec_count
            continue

        if OP_GET_LOCAL <= instr <= OP_SET_GLOBAL:
            _, i = _leb128(wasm, i)
            continue

        if instr in (OP_TABLE_GET, OP_TABLE_SET, OP_PREFIX_FC):
            if instr != OP_PREFIX_FC:
                _, i = _leb128(wasm, i)
                continue
            fc_type, i = _leb128(wasm, i)
            _require(i)
            if 12 <= fc_type <= 17:
                _, i = _leb128(wasm, i)
                if fc_type in (12, 14):
                    _, i = _leb128(wasm, i)
            elif fc_type == 8:
                _, i = _leb128(wasm, i)
                i += 1
            elif fc_type == 9:
                _, i = _leb128(wasm, i)
            elif fc_type == 10:
                if rules_version & GUARD_RULE_FIX_20250131:
                    raise GuardError("memory.copy is not allowed", codesec, i)
                i += 2
            elif fc_type == 11:
                if rules_version & GUARD_RULE_FIX_20250131:
                    raise GuardError("memory.fill is not allowed", codesec, i)
                i += 1
            elif fc_type <= 7:
                pass
            else:
                raise GuardError(f"Illegal 0xFC instruction: {fc_type}", codesec, i)
            continue

        if MEMOP_FIRST <= instr <= MEMOP_LAST:
            _, i = _leb128(wasm, i)
            _, i = _leb128(wasm, i)
            continue

        if instr == OP_CURRENT_MEMORY:
            i += 1
            continue
        if instr == OP_GROW_MEMORY:
            raise GuardError("memory.grow is disallowed in hooks", codesec, i)

        if instr in (OP_I32_CONST, OP_I64_CONST):
            _, i = _signed_leb128(wasm, i)
            continue
        if instr == OP_F32_CONST:
            i += 4
            continue
        if instr == OP_F64_CONST:
            i += 8
            continue

        if NUMOP_FIRST <= instr <= NUMOP_LAST:
            continue

        if instr == OP_PREFIX_FD:
            v, i = _leb128(wasm, i)
            if v <= 11:
                _, i = _leb128(wasm, i)
                _, i = _leb128(wasm, i)
            elif 84 <= v <= 91:
                _, i = _leb128(wasm, i)
                _, i = _leb128(wasm, i)
                i += 1
            elif 21 <= v <= 34:
                i += 1
            elif v in (12, 13):
                i += 16
            continue

        raise GuardError(f"Unknown instruction opcode: 0x{instr:02X}", codesec, i)

    return _compute_wce(root)


# ---------------------------------------------------------------------------
# validate_guards — top-level entry point
# ---------------------------------------------------------------------------

def validate_guards(
    wasm: bytes,
    import_whitelist: set[str] | None = None,
    rules_version: int = 0,
) -> GuardResult:
    """Validate guard calls in a WASM hook binary.

    Can accept either raw bytes or work with a pre-decoded Module.

    Args:
        wasm: Raw WASM binary bytes
        import_whitelist: Set of allowed import names. None = allow all.
        rules_version: Bitmask for guard rule versions

    Returns:
        GuardResult with worst-case execution counts

    Raises:
        GuardError: If validation fails
    """
    mod = decode_module(wasm)
    return validate_guards_module(mod, wasm, import_whitelist, rules_version)


def validate_guards_module(
    mod: Module,
    wasm: bytes,
    import_whitelist: set[str] | None = None,
    rules_version: int = 0,
) -> GuardResult:
    """Validate guards using a pre-decoded Module + raw bytes.

    The Module provides structural info (imports, exports, types).
    The raw bytes are needed for instruction-level walking.
    """
    # Custom sections not allowed
    if mod.custom_sections:
        raise GuardError("Hook contains custom sections (use cleaner to strip)")

    # Must import _g
    guard_idx = mod.guard_func_idx
    if guard_idx is None:
        raise GuardError("Hook did not import _g (guard function)")

    # Check import whitelist
    if import_whitelist is not None:
        for imp in mod.imports:
            if imp.module != "env":
                raise GuardError(f"Import module must be 'env', got '{imp.module}'")
            if imp.name not in import_whitelist:
                raise GuardError(f"Import '{imp.name}' not in whitelist")

    last_import_idx = mod.import_count - 1

    # Must export hook()
    hook_exp = mod.hook_export
    if hook_exp is None:
        raise GuardError("Hook did not export 'hook' function")

    cbak_exp = mod.cbak_export

    # Validate hook/cbak type signatures
    hook_type_idx = mod.func_type_idx(hook_exp.index)
    if hook_type_idx < len(mod.types):
        if not mod.types[hook_type_idx].is_hook_type:
            raise GuardError("hook() must be int64_t(uint32_t)")
    if cbak_exp is not None:
        cbak_type_idx = mod.func_type_idx(cbak_exp.index)
        if cbak_type_idx != hook_type_idx:
            raise GuardError("hook and cbak must have the same type signature")

    # Code indices (subtract import count)
    hook_code_idx = hook_exp.index - mod.import_count
    cbak_code_idx = cbak_exp.index - mod.import_count if cbak_exp else None

    # Walk code bodies
    code_bodies = decode_code_bodies_raw(wasm)
    hook_wce = 0
    cbak_wce = 0

    for j, (body_start, body_end) in enumerate(code_bodies):
        wce = _check_guard(
            wasm, j, body_start, body_end,
            guard_idx, last_import_idx, rules_version,
        )
        if wce >= MAX_WCE:
            raise GuardError(
                f"Worst-case execution {wce} exceeds limit {MAX_WCE} "
                f"in code section {j}")
        if j == hook_code_idx:
            hook_wce = wce
        elif cbak_code_idx is not None and j == cbak_code_idx:
            cbak_wce = wce

    return GuardResult(
        hook_wce=hook_wce,
        cbak_wce=cbak_wce,
        import_count=mod.import_count,
        guard_func_idx=guard_idx,
        hook_func_idx=hook_exp.index,
        cbak_func_idx=cbak_exp.index if cbak_exp else None,
    )
