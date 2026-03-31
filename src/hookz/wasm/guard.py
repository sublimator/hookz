"""Guard checker + WCE analysis for WASM hooks.

Three layers:
1. _walk_code() — builds BlockInfo tree from raw bytecode. Best-effort,
   never raises on malformed guards — just records what it finds.
2. validate_guards() — structural validation (canonical guard patterns,
   import whitelist, call restrictions). Raises GuardError on violations.
3. analyze_wce() — computes WCE from a Module. Returns results even if
   guards are non-canonical.
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

from .types import Module, ValType
from .decode import decode_module, decode_code_bodies_raw

log = logging.getLogger("hookz.guard")

# Limits from xahaud Enum.h
MAX_GUARD_CALLS = 1024
MAX_WCE = 0xFFFF
MAX_NESTING = 16

# Opcodes not in wasm-tob
OP_SELECT_T = 0x1C
OP_TABLE_GET = 0x25
OP_TABLE_SET = 0x26
OP_REF_NULL = 0xD0
OP_REF_IS_NULL = 0xD1
OP_REF_FUNC = 0xD2
OP_PREFIX_FC = 0xFC
OP_PREFIX_FD = 0xFD

BLOCK_TYPE_VOID = 0x40
BLOCK_TYPE_BYTES = {
    ValType.I32, ValType.I64, ValType.F32, ValType.F64,
    ValType.V128, ValType.FUNCREF, ValType.EXTERNREF,
    BLOCK_TYPE_VOID,
}

MEMOP_FIRST = 0x28
MEMOP_LAST = 0x3E
NUMOP_FIRST = 0x45
NUMOP_LAST = 0xC4

GUARD_RULE_FIX_20250131 = 0x01


class GuardError(Exception):
    def __init__(self, message: str, codesec: int = -1, offset: int = -1):
        self.codesec = codesec
        self.offset = offset
        super().__init__(message)


@dataclass
class BlockInfo:
    """Block/loop info node in the WCE tree."""
    iteration_bound: int
    instruction_count: int = 0
    parent: BlockInfo | None = None
    children: list[BlockInfo] = field(default_factory=list)
    start_byte: int = 0
    is_loop: bool = False
    guard_id: int = 0
    guard_canonical: bool = False  # True if loop had proper _g pattern

    def add_child(self, iteration_bound: int, start_byte: int,
                  is_loop: bool = False, guard_id: int = 0,
                  guard_canonical: bool = False) -> BlockInfo:
        child = BlockInfo(
            iteration_bound=iteration_bound, parent=self,
            start_byte=start_byte, is_loop=is_loop,
            guard_id=guard_id, guard_canonical=guard_canonical,
        )
        self.children.append(child)
        return child

    @property
    def wce(self) -> int:
        return _compute_wce(self)


@dataclass
class GuardResult:
    hook_wce: int
    cbak_wce: int
    import_count: int
    guard_func_idx: int
    hook_func_idx: int
    cbak_func_idx: int | None
    hook_tree: BlockInfo | None = None
    cbak_tree: BlockInfo | None = None
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# LEB128
# ---------------------------------------------------------------------------

def _leb128(buf: bytes, offset: int) -> tuple[int, int]:
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
# WCE computation
# ---------------------------------------------------------------------------

def _compute_wce(blk: BlockInfo, level: int = 0) -> int:
    if level > MAX_NESTING:
        return 0  # don't raise — best effort
    wce = blk.instruction_count
    for child in blk.children:
        wce += _compute_wce(child, level + 1)
    if blk.parent is None or blk.parent.iteration_bound == 0:
        return wce
    multiplier = blk.iteration_bound / blk.parent.iteration_bound
    return max(int(wce * multiplier), 1)


# ---------------------------------------------------------------------------
# _walk_code — builds block tree, best-effort, never raises on bad guards
# ---------------------------------------------------------------------------

def _walk_code(
    wasm: bytes,
    codesec: int,
    start_offset: int,
    end_offset: int,
    guard_func_idx: int,
) -> tuple[BlockInfo, list[str]]:
    """Walk bytecode, build BlockInfo tree. Returns (root, errors).

    Best-effort: records errors but keeps going. Always returns a tree.
    """
    errors: list[str] = []
    block_depth = 0
    root = BlockInfo(iteration_bound=1, start_byte=start_offset)
    current = root

    i = start_offset
    while i < end_offset:
        if i >= len(wasm):
            errors.append(f"Code section {codesec} truncated at offset {i}")
            break

        instr = wasm[i]
        i += 1
        current.instruction_count += 1

        if instr in (OP_UNREACHABLE, OP_NOP, OP_ELSE):
            continue

        if instr in (OP_BLOCK, OP_LOOP, OP_IF):
            if i >= len(wasm):
                errors.append(f"Truncated after block/loop/if at {i}")
                break
            block_type = wasm[i]
            if block_type in BLOCK_TYPE_BYTES:
                i += 1
            else:
                _, i = _signed_leb128(wasm, i)

            iteration_bound = current.iteration_bound if current.parent else 1
            loop_guard_id = 0
            canonical = False

            if instr == OP_LOOP:
                # Try to parse canonical guard pattern
                try:
                    saved_i = i
                    if i < len(wasm) and wasm[i] == OP_I32_CONST:
                        i += 1
                        loop_guard_id, i = _signed_leb128(wasm, i)
                        if i < len(wasm) and wasm[i] == OP_I32_CONST:
                            i += 1
                            iteration_bound, i = _leb128(wasm, i)
                            if i < len(wasm) and wasm[i] == OP_CALL:
                                i += 1
                                call_idx, i = _leb128(wasm, i)
                                if call_idx == guard_func_idx and iteration_bound > 0:
                                    canonical = True
                                else:
                                    errors.append(
                                        f"Loop at {saved_i}: call target {call_idx} != guard {guard_func_idx}")
                                    i = saved_i  # rewind
                            else:
                                errors.append(f"Loop at {saved_i}: missing call after i32.const pair")
                                i = saved_i
                        else:
                            errors.append(f"Loop at {saved_i}: missing second i32.const")
                            i = saved_i
                    else:
                        errors.append(f"Loop at {saved_i}: missing first i32.const")
                        i = saved_i
                except (GuardError, IndexError):
                    errors.append(f"Loop at {saved_i}: parse error")
                    i = saved_i

            current = current.add_child(
                iteration_bound, i,
                is_loop=(instr == OP_LOOP),
                guard_id=loop_guard_id,
                guard_canonical=canonical,
            )
            block_depth += 1
            continue

        if instr == OP_END:
            block_depth -= 1
            if current.parent is not None:
                current = current.parent
            elif block_depth == -1 and i >= end_offset:
                break
            else:
                errors.append(f"Illegal block end at {i}")
                break
            continue

        # All remaining instructions — just advance past operands
        try:
            i = _skip_operands(wasm, instr, i)
        except (GuardError, IndexError):
            errors.append(f"Failed to skip instruction 0x{instr:02X} at {i}")
            break

    return root, errors


def _skip_operands(wasm: bytes, instr: int, i: int) -> int:
    """Advance past an instruction's operands."""
    if instr in (OP_BR, OP_BR_IF):
        _, i = _leb128(wasm, i)
        return i
    if instr == OP_BR_TABLE:
        vc, i = _leb128(wasm, i)
        for _ in range(vc):
            _, i = _leb128(wasm, i)
        _, i = _leb128(wasm, i)
        return i
    if instr == OP_RETURN:
        return i
    if instr == OP_CALL:
        _, i = _leb128(wasm, i)
        return i
    if instr == OP_CALL_INDIRECT:
        _, i = _leb128(wasm, i)
        _, i = _leb128(wasm, i)
        return i
    if OP_REF_NULL <= instr <= OP_REF_FUNC:
        if instr == OP_REF_NULL:
            i += 1
        elif instr == OP_REF_FUNC:
            _, i = _leb128(wasm, i)
        return i
    if instr in (OP_DROP, OP_SELECT):
        return i
    if instr == OP_SELECT_T:
        vc, i = _leb128(wasm, i)
        i += vc
        return i
    if OP_GET_LOCAL <= instr <= OP_SET_GLOBAL:
        _, i = _leb128(wasm, i)
        return i
    if instr in (OP_TABLE_GET, OP_TABLE_SET):
        _, i = _leb128(wasm, i)
        return i
    if instr == OP_PREFIX_FC:
        fc, i = _leb128(wasm, i)
        if 12 <= fc <= 17:
            _, i = _leb128(wasm, i)
            if fc in (12, 14):
                _, i = _leb128(wasm, i)
        elif fc == 8:
            _, i = _leb128(wasm, i)
            i += 1
        elif fc == 9:
            _, i = _leb128(wasm, i)
        elif fc == 10:
            i += 2
        elif fc == 11:
            i += 1
        return i
    if MEMOP_FIRST <= instr <= MEMOP_LAST:
        _, i = _leb128(wasm, i)
        _, i = _leb128(wasm, i)
        return i
    if instr == OP_CURRENT_MEMORY:
        i += 1
        return i
    if instr == OP_GROW_MEMORY:
        i += 1
        return i
    if instr in (OP_I32_CONST, OP_I64_CONST):
        _, i = _signed_leb128(wasm, i)
        return i
    if instr == OP_F32_CONST:
        return i + 4
    if instr == OP_F64_CONST:
        return i + 8
    if NUMOP_FIRST <= instr <= NUMOP_LAST:
        return i
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
        return i
    return i  # unknown — assume no operands


# ---------------------------------------------------------------------------
# validate_guards — strict validation, raises on violations
# ---------------------------------------------------------------------------

def _check_guard_strict(
    wasm: bytes,
    codesec: int,
    start_offset: int,
    end_offset: int,
    guard_func_idx: int,
    last_import_idx: int,
    rules_version: int = 0,
) -> BlockInfo:
    """Strict guard validation. Raises GuardError on any violation."""
    tree, errors = _walk_code(wasm, codesec, start_offset, end_offset, guard_func_idx)

    # Walk errors are fatal in strict mode
    if errors:
        raise GuardError(errors[0], codesec, start_offset)

    # Check all loops have canonical guards
    def _check_loops(node: BlockInfo) -> None:
        if node.is_loop and not node.guard_canonical:
            raise GuardError(
                f"Loop at offset {node.start_byte} does not have canonical guard pattern",
                codesec, node.start_byte)
        for child in node.children:
            _check_loops(child)

    _check_loops(tree)

    # Check no calls to non-imported functions and no call_indirect
    # (This requires a second walk since _walk_code doesn't check these)
    _validate_calls(wasm, codesec, start_offset, end_offset,
                    guard_func_idx, last_import_idx, rules_version)

    return tree


def _validate_calls(
    wasm: bytes, codesec: int, start: int, end: int,
    guard_func_idx: int, last_import_idx: int, rules_version: int,
) -> None:
    """Validate call targets and disallowed instructions."""
    i = start
    guard_count = 0
    while i < end:
        if i >= len(wasm):
            break
        instr = wasm[i]
        i += 1

        if instr in (OP_BLOCK, OP_LOOP, OP_IF):
            bt = wasm[i] if i < len(wasm) else BLOCK_TYPE_VOID
            if bt in BLOCK_TYPE_BYTES:
                i += 1
            else:
                _, i = _signed_leb128(wasm, i)
            if instr == OP_LOOP:
                # Skip the guard pattern (already validated by _check_loops)
                if i < len(wasm) and wasm[i] == OP_I32_CONST:
                    i += 1
                    _, i = _signed_leb128(wasm, i)
                    if i < len(wasm) and wasm[i] == OP_I32_CONST:
                        i += 1
                        _, i = _leb128(wasm, i)
                        if i < len(wasm) and wasm[i] == OP_CALL:
                            i += 1
                            _, i = _leb128(wasm, i)
            continue

        if instr == OP_CALL:
            callee, i = _leb128(wasm, i)
            if callee > last_import_idx:
                raise GuardError(
                    f"Call to function {callee} outside imports (last={last_import_idx})",
                    codesec, i)
            if callee == guard_func_idx:
                guard_count += 1
                if guard_count > MAX_GUARD_CALLS:
                    raise GuardError("Too many guard calls", codesec, i)
            continue

        if instr == OP_CALL_INDIRECT:
            raise GuardError("call_indirect disallowed", codesec, i)

        if instr == OP_GROW_MEMORY:
            raise GuardError("memory.grow disallowed", codesec, i)

        if instr == OP_PREFIX_FC:
            fc, i = _leb128(wasm, i)
            if fc == 10 and (rules_version & GUARD_RULE_FIX_20250131):
                raise GuardError("memory.copy not allowed", codesec, i)
            if fc == 11 and (rules_version & GUARD_RULE_FIX_20250131):
                raise GuardError("memory.fill not allowed", codesec, i)
            # Skip remaining operands
            i = _skip_operands(wasm, OP_PREFIX_FC, i - 1)  # hacky but works
            continue

        try:
            i = _skip_operands(wasm, instr, i)
        except (GuardError, IndexError):
            break


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_guards(
    wasm: bytes,
    import_whitelist: set[str] | None = None,
    rules_version: int = 0,
) -> GuardResult:
    """Strict guard validation. Raises GuardError on any violation."""
    mod = decode_module(wasm)
    return validate_guards_module(mod, wasm, import_whitelist, rules_version)


def validate_guards_module(
    mod: Module,
    wasm: bytes,
    import_whitelist: set[str] | None = None,
    rules_version: int = 0,
) -> GuardResult:
    """Strict validation using a pre-decoded Module."""
    if mod.custom_sections:
        raise GuardError("Hook contains custom sections (use cleaner to strip)")

    guard_idx = mod.guard_func_idx
    if guard_idx is None:
        raise GuardError("Hook did not import _g")

    if import_whitelist is not None:
        for imp in mod.imports:
            if imp.module != "env":
                raise GuardError(f"Import module must be 'env', got '{imp.module}'")
            if imp.name not in import_whitelist:
                raise GuardError(f"Import '{imp.name}' not in whitelist")

    last_import_idx = mod.import_count - 1

    hook_exp = mod.hook_export
    if hook_exp is None:
        raise GuardError("Hook did not export 'hook'")
    cbak_exp = mod.cbak_export

    hook_type_idx = mod.func_type_idx(hook_exp.index)
    if hook_type_idx < len(mod.types) and not mod.types[hook_type_idx].is_hook_type:
        raise GuardError("hook() must be int64_t(uint32_t)")
    if cbak_exp is not None:
        cbak_type_idx = mod.func_type_idx(cbak_exp.index)
        if cbak_type_idx != hook_type_idx:
            raise GuardError("hook and cbak must have the same type signature")

    hook_code_idx = hook_exp.index - mod.import_count
    cbak_code_idx = cbak_exp.index - mod.import_count if cbak_exp else None

    code_bodies = decode_code_bodies_raw(wasm)
    hook_wce = 0
    cbak_wce = 0
    hook_tree = None
    cbak_tree = None

    for j, (body_start, body_end) in enumerate(code_bodies):
        tree = _check_guard_strict(
            wasm, j, body_start, body_end,
            guard_idx, last_import_idx, rules_version,
        )
        wce = tree.wce
        if wce >= MAX_WCE:
            raise GuardError(f"WCE {wce} exceeds limit {MAX_WCE} in code section {j}")
        if j == hook_code_idx:
            hook_wce = wce
            hook_tree = tree
        elif cbak_code_idx is not None and j == cbak_code_idx:
            cbak_wce = wce
            cbak_tree = tree

    return GuardResult(
        hook_wce=hook_wce, cbak_wce=cbak_wce,
        import_count=mod.import_count, guard_func_idx=guard_idx,
        hook_func_idx=hook_exp.index,
        cbak_func_idx=cbak_exp.index if cbak_exp else None,
        hook_tree=hook_tree, cbak_tree=cbak_tree,
    )


def analyze_wce(
    wasm: bytes,
) -> GuardResult:
    """Best-effort WCE analysis. Never raises — returns results + errors.

    Works on debug builds, dirty guards, whatever. Always returns a tree.
    """
    mod = decode_module(wasm)
    return analyze_wce_module(mod, wasm)


def analyze_wce_module(
    mod: Module,
    wasm: bytes,
) -> GuardResult:
    """Best-effort WCE analysis on a pre-decoded Module."""
    all_errors: list[str] = []

    guard_idx = mod.guard_func_idx
    if guard_idx is None:
        all_errors.append("No _g import found — WCE estimates will be inaccurate")
        guard_idx = -1  # won't match any call

    hook_exp = mod.hook_export
    cbak_exp = mod.cbak_export

    if hook_exp is None:
        all_errors.append("No hook() export found")
        return GuardResult(
            hook_wce=0, cbak_wce=0, import_count=mod.import_count,
            guard_func_idx=guard_idx, hook_func_idx=-1, cbak_func_idx=None,
            errors=all_errors,
        )

    hook_code_idx = hook_exp.index - mod.import_count
    cbak_code_idx = cbak_exp.index - mod.import_count if cbak_exp else None

    try:
        code_bodies = decode_code_bodies_raw(wasm)
    except Exception as e:
        all_errors.append(f"Failed to decode code section: {e}")
        return GuardResult(
            hook_wce=0, cbak_wce=0, import_count=mod.import_count,
            guard_func_idx=guard_idx, hook_func_idx=hook_exp.index,
            cbak_func_idx=cbak_exp.index if cbak_exp else None,
            errors=all_errors,
        )

    hook_wce = 0
    cbak_wce = 0
    hook_tree = None
    cbak_tree = None

    for j, (body_start, body_end) in enumerate(code_bodies):
        tree, errors = _walk_code(wasm, j, body_start, body_end, guard_idx)
        all_errors.extend(errors)
        wce = tree.wce
        if j == hook_code_idx:
            hook_wce = wce
            hook_tree = tree
        elif cbak_code_idx is not None and j == cbak_code_idx:
            cbak_wce = wce
            cbak_tree = tree

    return GuardResult(
        hook_wce=hook_wce, cbak_wce=cbak_wce,
        import_count=mod.import_count, guard_func_idx=guard_idx,
        hook_func_idx=hook_exp.index,
        cbak_func_idx=cbak_exp.index if cbak_exp else None,
        hook_tree=hook_tree, cbak_tree=cbak_tree,
        errors=all_errors,
    )
