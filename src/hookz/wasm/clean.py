"""Hook cleaner — strip sections, rewrite guards, rebuild exports.

Port of hook-cleaner-c/cleaner.c. Transforms a compiler-emitted WASM
binary into a production-ready Xahau hook by:

1. Stripping custom sections, table, start, element sections
2. Keeping only hook() and cbak() function bodies
3. Rebuilding type/import/function/export sections with remapped indices
4. Rewriting guard calls to canonical form at loop tops
"""

from __future__ import annotations

import logging

from wasm_tob import (
    OP_UNREACHABLE, OP_NOP, OP_BLOCK, OP_LOOP, OP_IF, OP_ELSE, OP_END,
    OP_BR, OP_BR_IF, OP_BR_TABLE, OP_RETURN, OP_CALL, OP_CALL_INDIRECT,
    OP_DROP, OP_SELECT,
    OP_GET_LOCAL, OP_SET_LOCAL, OP_TEE_LOCAL, OP_GET_GLOBAL, OP_SET_GLOBAL,
    OP_I32_CONST, OP_I64_CONST, OP_F32_CONST, OP_F64_CONST,
    OP_CURRENT_MEMORY, OP_GROW_MEMORY,
)

from .types import (
    WASM_HEADER,
    SectionId,
    ExportKind,
    Module,
    FuncType,
    Import,
    Export,
    CodeBody,
    LocalDecl,
    ValType,
)
from .decode import decode_module
from .encode import encode_module, _encode_leb128, _encode_signed_leb128
from .visitor import Visitor, KeepDebugVisitor, Action, LoopContext, InstructionContext

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

# Memory load/store range
MEMOP_FIRST = 0x28
MEMOP_LAST = 0x3E

# Numeric no-arg instruction range
NUMOP_FIRST = 0x45
NUMOP_LAST = 0xC4

log = logging.getLogger("hookz.clean")


class CleanError(Exception):
    """Raised when cleaning fails."""


def clean_hook(wasm: bytes, visitor: Visitor | None = None) -> bytes:
    """Clean a WASM hook binary for deployment.

    Args:
        wasm: Raw WASM binary (e.g. from clang/wasi-sdk)
        visitor: Visitor to control cleaning behavior. Default strips everything.

    Returns:
        Cleaned WASM binary bytes

    Raises:
        CleanError: If the binary can't be cleaned
    """
    if visitor is None:
        visitor = Visitor()
    mod = decode_module(wasm)
    original_size = len(wasm)
    cleaned = clean_module(mod, visitor)
    result = encode_module(cleaned)
    visitor.on_complete(original_size, len(result))
    return result


def clean_module(mod: Module, visitor: Visitor | None = None) -> Module:
    """Clean a decoded Module.

    - Strips/keeps sections based on visitor decisions
    - Keeps only imports that are function imports
    - Rebuilds type section with only used types
    - Keeps only hook/cbak code bodies
    - Rebuilds export section with only hook/cbak
    - Rewrites guard calls in code bodies to canonical form
    """
    hook_exp = mod.hook_export
    if hook_exp is None:
        raise CleanError("No hook() export found")
    cbak_exp = mod.cbak_export

    guard_idx = mod.guard_func_idx
    if guard_idx is None:
        raise CleanError("No _g import found")

    import_count = mod.import_count

    # Find hook/cbak code indices
    hook_code_idx = hook_exp.index - import_count
    cbak_code_idx = cbak_exp.index - import_count if cbak_exp else None

    if hook_code_idx < 0 or hook_code_idx >= len(mod.code):
        raise CleanError(f"hook() code index {hook_code_idx} out of range")
    if cbak_code_idx is not None and (cbak_code_idx < 0 or cbak_code_idx >= len(mod.code)):
        raise CleanError(f"cbak() code index {cbak_code_idx} out of range")

    # --- Determine which types are used ---
    used_type_indices = set()
    for imp in mod.imports:
        used_type_indices.add(imp.type_idx)

    # Hook/cbak type
    hook_type_idx = mod.functions[hook_code_idx] if hook_code_idx < len(mod.functions) else None

    # Find or create the hook/cbak type: int64_t(uint32_t)
    hook_cbak_type = FuncType(params=(ValType.I32,), results=(ValType.I64,))
    hook_cbak_new_idx = None

    # Build new type list: used import types + hook/cbak type
    old_to_new_type: dict[int, int] = {}
    new_types: list[FuncType] = []

    for old_idx in sorted(used_type_indices):
        if old_idx < len(mod.types):
            old_to_new_type[old_idx] = len(new_types)
            ft = mod.types[old_idx]
            new_types.append(ft)
            if ft.is_hook_type:
                hook_cbak_new_idx = old_to_new_type[old_idx]

    if hook_cbak_new_idx is None:
        hook_cbak_new_idx = len(new_types)
        new_types.append(hook_cbak_type)

    # --- Rebuild imports with remapped type indices ---
    new_imports = []
    for imp in mod.imports:
        new_type_idx = old_to_new_type.get(imp.type_idx, imp.type_idx)
        new_imports.append(Import(module=imp.module, name=imp.name, type_idx=new_type_idx))

    new_guard_idx = None
    for i, imp in enumerate(new_imports):
        if imp.name == "_g":
            new_guard_idx = i
            break

    # --- Build code bodies (hook + optionally cbak) ---
    # Rewrite guards in the code bodies
    hook_body = _rewrite_guards(mod.code[hook_code_idx], guard_idx)
    new_code = [hook_body]
    new_functions = [hook_cbak_new_idx]

    if cbak_code_idx is not None:
        cbak_body = _rewrite_guards(mod.code[cbak_code_idx], guard_idx)
        new_code.append(cbak_body)
        new_functions.append(hook_cbak_new_idx)

    # --- Build exports ---
    new_import_count = len(new_imports)

    # Determine order: if cbak was before hook in original, preserve that
    cbak_first = cbak_exp is not None and cbak_exp.index < hook_exp.index

    new_exports = []
    if cbak_first and cbak_exp is not None:
        new_exports.append(Export(name="cbak", kind=ExportKind.FUNC, index=new_import_count))
        new_exports.append(Export(name="hook", kind=ExportKind.FUNC, index=new_import_count + 1))
    else:
        new_exports.append(Export(name="hook", kind=ExportKind.FUNC, index=new_import_count))
        if cbak_exp is not None:
            new_exports.append(Export(name="cbak", kind=ExportKind.FUNC, index=new_import_count + 1))

    # --- Custom sections ---
    if visitor is None:
        visitor = Visitor()

    kept_custom = []
    for cs in mod.custom_sections:
        action = visitor.on_custom_section(cs.name, len(cs.data))
        if action == Action.KEEP:
            kept_custom.append(cs)

    # --- Assemble cleaned module ---
    cleaned = Module(
        types=new_types,
        imports=new_imports,
        functions=new_functions,
        exports=new_exports,
        code=new_code,
        memories=mod.memories,
        globals=mod.globals,
        data=mod.data,
        custom_sections=kept_custom,
    )

    return cleaned


# ---------------------------------------------------------------------------
# Guard rewriting
# ---------------------------------------------------------------------------

def _rewrite_guards(body: CodeBody, guard_func_idx: int) -> CodeBody:
    """Rewrite guard calls in a code body to canonical loop-top form.

    Scans for the pattern: i32.const <id>, i32.const <maxiter>, call <_g>, drop
    If found away from loop top, reconstructs and moves to loop top.
    If "dirty" (other instructions between consts and call), reconstructs
    a clean guard and inserts at loop top, NOP-filling the original.
    """
    code = bytearray(body.code)
    result = _rewrite_guards_in_bytecode(code, guard_func_idx)
    return CodeBody(locals=body.locals, code=bytes(result))


def _rewrite_guards_in_bytecode(code: bytearray, guard_func_idx: int) -> bytearray:
    """Walk bytecode, find guard patterns, rewrite to canonical form.

    Returns new bytecode with guards at loop tops.
    """
    out = bytearray()

    # State for guard finder
    last_loop_out_pos = -1  # position in output where last loop body starts
    i32_found = 0
    call_guard_out_pos = -1  # position in output of call _g
    last_i32_val = 0
    second_last_i32_val = 0
    last_i32_out_pos = -1
    second_last_i32_out_pos = -1
    between_const_and_guard = 0

    def reset():
        nonlocal i32_found, call_guard_out_pos, last_i32_val, second_last_i32_val
        nonlocal last_i32_out_pos, second_last_i32_out_pos, between_const_and_guard
        i32_found = 0
        call_guard_out_pos = -1
        last_i32_val = 0
        second_last_i32_val = 0
        last_i32_out_pos = -1
        second_last_i32_out_pos = -1
        between_const_and_guard = 0

    i = 0
    while i < len(code):
        instr_start = i
        ins = code[i]
        i += 1

        # block, loop, if
        if ins in (OP_BLOCK, OP_LOOP, OP_IF):
            block_type = code[i] if i < len(code) else BLOCK_TYPE_VOID
            if block_type in BLOCK_TYPE_BYTES:
                i += 1
            else:
                _, i = _skip_signed_leb(code, i)

            out.extend(code[instr_start:i])
            if ins == OP_LOOP:
                last_loop_out_pos = len(out)
            reset()
            continue

        # drop — trigger for guard detection
        if ins == OP_DROP:
            out.append(ins)
            if i32_found >= 2 and call_guard_out_pos >= 0 and last_loop_out_pos >= 0:
                # Found a guard pattern! Rewrite it.
                # The guard ID has bit 31 set (from _g macro: (1<<31) + __LINE__)
                # The maxiter is always a small positive number.
                # Identify which is which by checking bit 31.
                val_a = second_last_i32_val
                val_b = last_i32_val
                if (val_a & 0x80000000) or (val_a < 0):
                    guard_id, maxiter = val_a, val_b
                else:
                    guard_id, maxiter = val_b, val_a

                # Build canonical guard: i32.const <id>, i32.const <maxiter>, call <_g>, drop
                # Both values are encoded as signed LEB128 (i32.const is always signed)
                guard = bytearray()
                guard.append(OP_I32_CONST)
                guard.extend(_encode_signed_leb128(guard_id))
                guard.append(OP_I32_CONST)
                guard.extend(_encode_signed_leb128(maxiter))
                guard.append(OP_CALL)
                guard.extend(_encode_leb128(guard_func_idx))
                guard.append(OP_DROP)

                if between_const_and_guard > 0:
                    # Dirty guard: NOP-fill the original guard location in output,
                    # then insert canonical guard at loop top
                    # NOP from second_last_i32_out_pos to current position (the drop we just wrote)
                    nop_start = second_last_i32_out_pos
                    nop_end = len(out)
                    for j in range(nop_start, nop_end):
                        out[j] = OP_NOP

                    # Insert guard at loop top
                    loop_pos = last_loop_out_pos
                    rest = bytes(out[loop_pos:])
                    out[loop_pos:] = guard + rest

                    log.debug("Dirty guard rewritten: _g(0x%08X, %d) at loop offset %d",
                              guard_id, maxiter, loop_pos)
                else:
                    # Clean guard but misplaced: move to loop top
                    guard_start = second_last_i32_out_pos
                    guard_end = len(out)  # includes the drop
                    guard_bytes = bytes(out[guard_start:guard_end])

                    # Remove from current position
                    del out[guard_start:guard_end]

                    # Insert at loop top
                    loop_pos = last_loop_out_pos
                    rest = bytes(out[loop_pos:])
                    out[loop_pos:] = guard_bytes + rest

                    log.debug("Clean guard moved to loop top at offset %d", loop_pos)

                last_loop_out_pos = -1  # prevent double move
            reset()
            continue

        # call
        if ins == OP_CALL:
            call_out_start = len(out)
            func_idx, i = _parse_leb(code, i)
            out.extend(code[instr_start:i])
            if func_idx == guard_func_idx:
                call_guard_out_pos = call_out_start
            else:
                reset()
            continue

        # i32.const
        if ins == OP_I32_CONST:
            second_last_i32_out_pos = last_i32_out_pos
            second_last_i32_val = last_i32_val
            last_i32_out_pos = len(out)
            val, i = _parse_signed_leb(code, i)
            last_i32_val = val
            out.extend(code[instr_start:i])
            i32_found += 1
            continue

        # Any other instruction: copy through, track if between consts and guard
        if i32_found > 0:
            between_const_and_guard += 1

        # Parse instruction to advance i properly, then copy bytes
        i = _skip_instruction(code, ins, i)
        out.extend(code[instr_start:i])

    return out


# ---------------------------------------------------------------------------
# Instruction skipping helpers (for bytecode walking without wasm-tob)
# ---------------------------------------------------------------------------

def _parse_leb(buf: bytearray, offset: int) -> tuple[int, int]:
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
    return val, i


def _parse_signed_leb(buf: bytearray, offset: int) -> tuple[int, int]:
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
    return val, i


def _skip_signed_leb(buf: bytearray, offset: int) -> tuple[int, int]:
    return _parse_signed_leb(buf, offset)


def _skip_instruction(code: bytearray, ins: int, i: int) -> int:
    """Advance past an instruction's operands. Returns new offset."""
    # br_table
    if ins == OP_BR_TABLE:
        vec_count, i = _parse_leb(code, i)
        for _ in range(vec_count):
            _, i = _parse_leb(code, i)
        _, i = _parse_leb(code, i)
        return i

    # Single byte: no operands
    if ins in (OP_UNREACHABLE, OP_NOP, OP_ELSE, OP_END, OP_RETURN,
               OP_DROP, OP_SELECT, OP_REF_IS_NULL):
        return i
    if NUMOP_FIRST <= ins <= NUMOP_LAST:
        return i

    # Single LEB operand
    if ins in (OP_BR, OP_BR_IF, OP_CALL, OP_REF_NULL, OP_REF_FUNC,
               OP_TABLE_GET, OP_TABLE_SET, OP_I64_CONST):
        _, i = _parse_leb(code, i)
        return i
    if OP_GET_LOCAL <= ins <= OP_SET_GLOBAL:
        _, i = _parse_leb(code, i)
        return i

    # call_indirect: two LEBs
    if ins == OP_CALL_INDIRECT:
        _, i = _parse_leb(code, i)
        _, i = _parse_leb(code, i)
        return i

    # select t*: LEB count + that many type bytes
    if ins == OP_SELECT_T:
        vc, i = _parse_leb(code, i)
        i += vc
        return i

    # memory load/store: two LEBs (align + offset)
    if MEMOP_FIRST <= ins <= MEMOP_LAST:
        _, i = _parse_leb(code, i)
        _, i = _parse_leb(code, i)
        return i

    # memory.size / memory.grow: 1 byte (memory index)
    if ins in (OP_CURRENT_MEMORY, OP_GROW_MEMORY):
        i += 1
        return i

    # i32.const: signed LEB
    if ins == OP_I32_CONST:
        _, i = _parse_signed_leb(code, i)
        return i

    # f32.const: 4 raw bytes
    if ins == OP_F32_CONST:
        return i + 4

    # f64.const: 8 raw bytes
    if ins == OP_F64_CONST:
        return i + 8

    # 0xFC multi-byte prefix
    if ins == OP_PREFIX_FC:
        fc_type, i = _parse_leb(code, i)
        if 12 <= fc_type <= 17:  # table instructions
            _, i = _parse_leb(code, i)
            if fc_type in (12, 14):  # table.init, table.copy
                _, i = _parse_leb(code, i)
        elif fc_type == 8:   # memory.init
            _, i = _parse_leb(code, i)
            i += 1
        elif fc_type == 9:   # data.drop
            _, i = _parse_leb(code, i)
        elif fc_type == 10:  # memory.copy
            i += 2
        elif fc_type == 11:  # memory.fill
            i += 1
        return i

    # 0xFD SIMD prefix
    if ins == OP_PREFIX_FD:
        v, i = _parse_leb(code, i)
        if v <= 11:          # memargs
            _, i = _parse_leb(code, i)
            _, i = _parse_leb(code, i)
        elif 84 <= v <= 91:  # memargs + laneidx
            _, i = _parse_leb(code, i)
            _, i = _parse_leb(code, i)
            i += 1
        elif 21 <= v <= 34:  # laneidx
            i += 1
        elif v in (12, 13):  # v128.const / i8x16.shuffle
            i += 16
        return i

    # block/loop/if already handled before this is called
    return i
