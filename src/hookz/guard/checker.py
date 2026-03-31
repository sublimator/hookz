"""Guard checker — port of xahaud Guard.h.

Validates that a WASM hook binary:
1. Imports _g (guard function)
2. Every loop starts with i32.const, i32.const, call _g
3. Only calls imported functions (no internal function calls)
4. No call_indirect, no memory.grow
5. Exports hook() and optionally cbak()
6. Worst-case execution count < 65535

Uses wasm-tob for section parsing + raw byte walking for code analysis
(matching the C++ approach of walking opcodes with LEB128 parsing).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from wasm_tob import (
    OP_UNREACHABLE, OP_NOP, OP_BLOCK, OP_LOOP, OP_IF, OP_ELSE, OP_END,
    OP_BR, OP_BR_IF, OP_BR_TABLE, OP_RETURN, OP_CALL, OP_CALL_INDIRECT,
    OP_DROP, OP_SELECT,
    OP_GET_LOCAL, OP_SET_LOCAL, OP_TEE_LOCAL, OP_GET_GLOBAL, OP_SET_GLOBAL,
    OP_I32_CONST, OP_I64_CONST, OP_F32_CONST, OP_F64_CONST,
    OP_CURRENT_MEMORY, OP_GROW_MEMORY,
    SEC_TYPE, SEC_IMPORT, SEC_FUNCTION, SEC_EXPORT, SEC_CODE, SEC_UNK,
)

log = logging.getLogger("hookz.guard")

# WASM header: magic number + version 1.0
WASM_HEADER = b"\x00\x61\x73\x6D\x01\x00\x00\x00"
WASM_HEADER_SIZE = 8
MIN_HOOK_SIZE = 63

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

# First/last memory load/store opcodes
MEMOP_FIRST = 0x28  # i32.load
MEMOP_LAST = 0x3E   # i64.store32

# First/last simple numeric opcodes (no arguments)
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

    hook_wce: int  # worst-case execution count for hook()
    cbak_wce: int  # worst-case execution count for cbak() (0 if no cbak)
    import_count: int
    guard_func_idx: int
    hook_func_idx: int
    cbak_func_idx: int | None


# ---------------------------------------------------------------------------
# LEB128 helpers (matching Guard.h parseLeb128 / parseSignedLeb128)
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
    """Mirrors WasmBlkInf from Guard.h."""

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
    """Compute worst-case execution count. Mirrors compute_wce from Guard.h."""
    if level > MAX_NESTING:
        raise GuardError("Maximum block nesting depth reached (16 levels)")

    wce = blk.instruction_count

    for child in blk.children:
        wce += _compute_wce(child, level + 1)

    if blk.parent is None or blk.parent.iteration_bound == 0:
        return wce

    multiplier = blk.iteration_bound / blk.parent.iteration_bound
    wce = int(wce * multiplier)
    return max(wce, 1)


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

        # --- No-op instructions ---
        if instr in (OP_UNREACHABLE, OP_NOP, OP_ELSE):
            continue

        # --- Block / Loop / If ---
        if instr in (OP_BLOCK, OP_LOOP, OP_IF):
            _require(i)
            block_type = wasm[i]
            if block_type in BLOCK_TYPE_BYTES:
                i += 1
            else:
                _, i = _signed_leb128(wasm, i)

            iteration_bound = current.iteration_bound if current.parent else 1

            if instr == OP_LOOP:
                # Guard pattern: i32.const <id>, i32.const <maxiter>, call <_g>
                _require(i)
                if wasm[i] != OP_I32_CONST:
                    raise GuardError(
                        "Missing first i32.const after loop", codesec, i)
                i += 1
                _, i = _signed_leb128(wasm, i)  # guard ID

                _require(i)
                if wasm[i] != OP_I32_CONST:
                    raise GuardError(
                        "Missing second i32.const after loop", codesec, i)
                i += 1
                iteration_bound, i = _leb128(wasm, i)

                if iteration_bound == 0:
                    raise GuardError(
                        "Guard call cannot specify 0 maxiter", codesec, i)

                _require(i)
                if wasm[i] != OP_CALL:
                    raise GuardError(
                        "Missing call to _g after i32.const pair at loop start",
                        codesec, i)
                i += 1
                call_idx, i = _leb128(wasm, i)

                if call_idx != guard_func_idx:
                    raise GuardError(
                        f"Call at loop start was not _g "
                        f"(called {call_idx}, expected {guard_func_idx})",
                        codesec, i)

                guard_count += 1
                if guard_count > MAX_GUARD_CALLS:
                    raise GuardError(
                        "Too many guard calls (limit 1024)", codesec, i)

            current = current.add_child(iteration_bound, i)
            block_depth += 1
            continue

        # --- End ---
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

        # --- Branch ---
        if instr in (OP_BR, OP_BR_IF):
            _, i = _leb128(wasm, i)
            continue

        if instr == OP_BR_TABLE:
            vec_count, i = _leb128(wasm, i)
            for _ in range(vec_count):
                _, i = _leb128(wasm, i)
            _, i = _leb128(wasm, i)  # default target
            continue

        # --- Return ---
        if instr == OP_RETURN:
            continue

        # --- Call ---
        if instr == OP_CALL:
            callee_idx, i = _leb128(wasm, i)
            if callee_idx > last_import_idx:
                raise GuardError(
                    f"Hook calls function {callee_idx} outside whitelisted "
                    f"imports (last import is {last_import_idx})",
                    codesec, i)
            if callee_idx == guard_func_idx:
                guard_count += 1
                if guard_count > MAX_GUARD_CALLS:
                    raise GuardError(
                        "Too many guard calls (limit 1024)", codesec, i)
            continue

        # --- Call indirect (disallowed) ---
        if instr == OP_CALL_INDIRECT:
            raise GuardError("call_indirect is disallowed in hooks", codesec, i)

        # --- Reference instructions ---
        if OP_REF_NULL <= instr <= OP_REF_FUNC:
            if instr == OP_REF_NULL:
                _require(i)
                if wasm[i] not in (0x70, 0x6F):
                    raise GuardError("Invalid reftype in ref.null", codesec, i)
                i += 1
            elif instr == OP_REF_FUNC:
                _, i = _leb128(wasm, i)
            continue

        # --- Parametric ---
        if instr in (OP_DROP, OP_SELECT, OP_SELECT_T):
            if instr == OP_SELECT_T:
                vec_count, i = _leb128(wasm, i)
                i += vec_count  # skip value types
            continue

        # --- Variable instructions ---
        if OP_GET_LOCAL <= instr <= OP_SET_GLOBAL:
            _, i = _leb128(wasm, i)
            continue

        # --- Table instructions + 0xFC prefix ---
        if instr in (OP_TABLE_GET, OP_TABLE_SET, OP_PREFIX_FC):
            if instr != OP_PREFIX_FC:
                _, i = _leb128(wasm, i)
                continue

            fc_type, i = _leb128(wasm, i)
            _require(i)

            if 12 <= fc_type <= 17:  # table instructions
                _, i = _leb128(wasm, i)
                if fc_type in (12, 14):  # table.init, table.copy
                    _, i = _leb128(wasm, i)
            elif fc_type == 8:  # memory.init
                _, i = _leb128(wasm, i)
                i += 1
            elif fc_type == 9:  # data.drop
                _, i = _leb128(wasm, i)
            elif fc_type == 10:  # memory.copy
                if rules_version & GUARD_RULE_FIX_20250131:
                    raise GuardError("memory.copy is not allowed", codesec, i)
                i += 2
            elif fc_type == 11:  # memory.fill
                if rules_version & GUARD_RULE_FIX_20250131:
                    raise GuardError("memory.fill is not allowed", codesec, i)
                i += 1
            elif fc_type <= 7:  # numeric saturating truncation (no params)
                pass
            else:
                raise GuardError(
                    f"Illegal 0xFC instruction: {fc_type}", codesec, i)
            continue

        # --- Memory load/store ---
        if MEMOP_FIRST <= instr <= MEMOP_LAST:
            _, i = _leb128(wasm, i)  # align
            _, i = _leb128(wasm, i)  # offset
            continue

        # --- memory.size / memory.grow ---
        if instr == OP_CURRENT_MEMORY:
            i += 1  # skip memory index
            continue
        if instr == OP_GROW_MEMORY:
            raise GuardError("memory.grow is disallowed in hooks", codesec, i)

        # --- Constants ---
        if instr in (OP_I32_CONST, OP_I64_CONST):
            _, i = _signed_leb128(wasm, i)
            continue
        if instr == OP_F32_CONST:
            i += 4
            continue
        if instr == OP_F64_CONST:
            i += 8
            continue

        # --- Numeric instructions (no arguments) ---
        if NUMOP_FIRST <= instr <= NUMOP_LAST:
            continue

        # --- Vector instructions (0xFD prefix) ---
        if instr == OP_PREFIX_FD:
            v, i = _leb128(wasm, i)
            if v <= 11:  # memargs
                _, i = _leb128(wasm, i)
                _, i = _leb128(wasm, i)
            elif 84 <= v <= 91:  # memargs + laneidx
                _, i = _leb128(wasm, i)
                _, i = _leb128(wasm, i)
                i += 1
            elif 21 <= v <= 34:  # laneidx
                i += 1
            elif v in (12, 13):  # v128.const / i8x16.shuffle
                i += 16
            continue

        raise GuardError(
            f"Unknown instruction opcode: 0x{instr:02X}", codesec, i)

    return _compute_wce(root)


# ---------------------------------------------------------------------------
# validate_guards — top-level validation (port of validateGuards)
# ---------------------------------------------------------------------------

def validate_guards(
    wasm: bytes,
    import_whitelist: set[str] | None = None,
    rules_version: int = 0,
) -> GuardResult:
    """Validate guard calls in a WASM hook binary.

    Args:
        wasm: Raw WASM binary bytes
        import_whitelist: Set of allowed import function names.
                         If None, all imports are allowed.
        rules_version: Bitmask for guard rule versions

    Returns:
        GuardResult with worst-case execution counts

    Raises:
        GuardError: If validation fails
    """
    if len(wasm) < MIN_HOOK_SIZE:
        raise GuardError("Hook too small (minimum 63 bytes)")

    if wasm[:WASM_HEADER_SIZE] != WASM_HEADER:
        raise GuardError("Invalid WASM magic number or version")

    # Parse sections using wasm-tob
    import wasm_tob

    sections: dict[int, Any] = {}
    for section in wasm_tob.decode_module(wasm):
        sec_id = section.data.id if hasattr(section.data, 'id') else -1
        if sec_id == SEC_UNK:  # custom section
            raise GuardError(
                "Hook contains a custom section (use cleaner to strip)")
        sections[sec_id] = section.data

    # --- Import section ---
    if SEC_IMPORT not in sections:
        raise GuardError("Hook did not import any functions")

    import_sec = sections[SEC_IMPORT]
    guard_func_idx = -1
    func_upto = 0

    for entry in import_sec.payload.entries:
        mod_name = bytes(entry.module_str).decode()
        func_name = bytes(entry.field_str).decode()

        if mod_name != "env":
            raise GuardError(f"Import module must be 'env', got '{mod_name}'")
        if entry.kind != 0:
            raise GuardError("Non-function import detected")
        if import_whitelist is not None and func_name not in import_whitelist:
            raise GuardError(f"Import '{func_name}' not in whitelist")
        if func_name == "_g":
            guard_func_idx = func_upto
        func_upto += 1

    if guard_func_idx == -1:
        raise GuardError("Hook did not import _g (guard function)")

    last_import_idx = func_upto - 1
    import_count = func_upto

    # --- Export section ---
    if SEC_EXPORT not in sections:
        raise GuardError("Hook did not export any functions")

    export_sec = sections[SEC_EXPORT]
    hook_func_idx: int | None = None
    cbak_func_idx: int | None = None

    for entry in export_sec.payload.entries:
        name = bytes(entry.field_str).decode()
        if name == "hook" and entry.kind == 0:
            hook_func_idx = entry.index
        elif name == "cbak" and entry.kind == 0:
            cbak_func_idx = entry.index

    if hook_func_idx is None:
        raise GuardError("Hook did not export 'hook' function")

    # --- Function section ---
    if SEC_FUNCTION not in sections:
        raise GuardError("Hook has no function section")

    func_sec = sections[SEC_FUNCTION]
    func_type_map: dict[int, int] = {}
    for j, type_idx in enumerate(func_sec.payload.types):
        func_type_map[j] = type_idx

    hook_code_idx = hook_func_idx - import_count
    cbak_code_idx = (cbak_func_idx - import_count
                     if cbak_func_idx is not None else None)

    # --- Type section — validate hook/cbak signatures ---
    if SEC_TYPE in sections:
        type_sec = sections[SEC_TYPE]
        if hook_code_idx in func_type_map:
            hook_type_idx = func_type_map[hook_code_idx]
            if hook_type_idx < len(type_sec.payload.entries):
                ft = type_sec.payload.entries[hook_type_idx]
                if ft.param_count != 1:
                    raise GuardError(
                        "hook() must take exactly one uint32_t parameter")
            if (cbak_code_idx is not None
                    and cbak_code_idx in func_type_map
                    and func_type_map[cbak_code_idx] != hook_type_idx):
                raise GuardError(
                    "hook and cbak must have the same type signature")

    # --- Code section — run guard check on each function ---
    if SEC_CODE not in sections:
        raise GuardError("Hook has no code section")

    code_bodies = _find_code_bodies(wasm)
    hook_wce = 0
    cbak_wce = 0

    for j, (body_start, body_end) in enumerate(code_bodies):
        wce = _check_guard(
            wasm, j, body_start, body_end,
            guard_func_idx, last_import_idx,
            rules_version,
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
        import_count=import_count,
        guard_func_idx=guard_func_idx,
        hook_func_idx=hook_func_idx,
        cbak_func_idx=cbak_func_idx,
    )


def _find_code_bodies(wasm: bytes) -> list[tuple[int, int]]:
    """Find raw byte ranges of function bodies in the WASM code section.

    Returns list of (start_offset, end_offset) for each function body's
    instructions (after locals have been skipped).
    """
    i = WASM_HEADER_SIZE
    while i < len(wasm):
        section_type = wasm[i]
        i += 1
        section_length, i = _leb128(wasm, i)
        next_section = i + section_length

        if section_type == SEC_CODE:
            func_count, i = _leb128(wasm, i)
            bodies = []
            for _ in range(func_count):
                code_size, i = _leb128(wasm, i)
                code_end = i + code_size

                # Skip locals declarations
                local_count, i = _leb128(wasm, i)
                for _ in range(local_count):
                    _, i = _leb128(wasm, i)  # count
                    i += 1  # value type

                bodies.append((i, code_end))
                i = code_end
            return bodies

        i = next_section

    raise GuardError("No code section found in WASM binary")
