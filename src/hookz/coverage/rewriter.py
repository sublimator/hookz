"""WASM binary rewriter — inject on_source_line(line, col) callbacks.

Reads DWARF .debug_line to get bytecode→source mapping, then injects a host
function call at every new source location.

WASM's structured control flow means inserting instructions never breaks
branches (they use nesting depth, not byte offsets). We only need to:
1. Add __on_source_line as a new import (and its type if needed)
2. Shift all existing call/ref.func function indices by 1
3. Insert i32.const line; i32.const col; call $idx at each DWARF line boundary

Section structure is handled by hookz.wasm (decode/encode); this module only
rewrites instruction bytes within function bodies.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hookz.wasm.decode import (
    code_section_content_offset,
    decode_code_bodies_raw,
    decode_module,
)
from hookz.wasm.encode import encode_module
from hookz.wasm.leb128 import read_signed, read_unsigned, write_signed, write_unsigned
from hookz.wasm.types import ExportKind, FuncType, Import, ValType


# ---- DWARF source locations ----

@dataclass
class SourceLoc:
    address: int  # bytecode offset relative to code section body
    line: int
    col: int


def _find_llvm_dwarfdump() -> list[str]:
    """Find llvm-dwarfdump, trying platform-appropriate methods."""
    import shutil
    import platform

    # Direct llvm-dwarfdump (Linux, or macOS with LLVM in PATH)
    if shutil.which("llvm-dwarfdump"):
        return ["llvm-dwarfdump"]

    # macOS: use xcrun to find it
    if platform.system() == "Darwin" and shutil.which("xcrun"):
        return ["xcrun", "llvm-dwarfdump"]

    # Try versioned names (common on Linux: llvm-dwarfdump-17, etc.)
    for ver in range(20, 14, -1):
        name = f"llvm-dwarfdump-{ver}"
        if shutil.which(name):
            return [name]

    raise RuntimeError(
        "llvm-dwarfdump not found. Install LLVM tools:\n"
        "  macOS: xcode-select --install\n"
        "  Linux: apt install llvm  (or llvm-17, etc.)"
    )


def parse_dwarf_locations(wasm_path_or_bytes: str | bytes) -> list[SourceLoc]:
    """Parse DWARF .debug_line via llvm-dwarfdump.

    Accepts a file path (str) or raw WASM bytes.
    """
    if isinstance(wasm_path_or_bytes, bytes):
        tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
        tmp.write(wasm_path_or_bytes)
        tmp.close()
        try:
            return parse_dwarf_locations(tmp.name)
        finally:
            Path(tmp.name).unlink(missing_ok=True)

    wasm_path = wasm_path_or_bytes
    cmd = _find_llvm_dwarfdump()
    r = subprocess.run(
        [*cmd, "--debug-line", wasm_path],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"llvm-dwarfdump failed: {r.stderr}")

    locs: list[SourceLoc] = []
    in_table = False
    for line in (r.stdout + r.stderr).splitlines():
        if "Address" in line and "Line" in line and "Column" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if line.strip() == "" or "end_sequence" in line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                ln = int(parts[1])
                col = int(parts[2])
                if ln > 0:
                    locs.append(SourceLoc(address=addr, line=ln, col=col))
            except (ValueError, IndexError):
                continue
    return locs


# ---- Code instrumentation ----

# WASM opcodes that take a function index as immediate
_CALL = 0x10
_REF_FUNC = 0xD2
_RETURN_CALL = 0x12

# Opcodes with known immediate sizes for skipping
_BLOCK_OPS = {0x02, 0x03, 0x04}  # block, loop, if — followed by blocktype
_BR_OPS = {0x0C, 0x0D}  # br, br_if — uleb128 label
_CALL_INDIRECT = 0x11  # uleb128 type + uleb128 table(0)
_LOCAL_OPS = {0x20, 0x21, 0x22}  # local.get/set/tee — uleb128
_GLOBAL_OPS = {0x23, 0x24}  # global.get/set — uleb128
_I32_CONST = 0x41  # sleb128
_I64_CONST = 0x42  # sleb128
_F32_CONST = 0x43  # 4 bytes
_F64_CONST = 0x44  # 8 bytes
_MEMORY_OPS = set(range(0x28, 0x3F))  # loads/stores — uleb128 align + uleb128 offset
_MEMORY_SIZE = 0x3F
_MEMORY_GROW = 0x40
_BR_TABLE = 0x0E  # uleb128 count + uleb128[] + uleb128 default


def _rewrite_code(
    code: bytes,
    callback_idx: int,
    locs_at: dict[int, SourceLoc],
    func_idx_shift: int,
) -> bytes:
    """Rewrite instruction bytes: shift call indices and insert callbacks.

    locs_at maps code-local byte offsets (0 = first instruction) to the
    source location that begins there.
    """
    new_code = bytearray()
    last_line_col: tuple[int, int] | None = None
    i = 0

    while i < len(code):
        # Check if this offset has a DWARF entry (new source location)
        if i in locs_at:
            loc = locs_at[i]
            lc = (loc.line, loc.col)
            if lc != last_line_col:
                # Insert: i32.const line; i32.const col; call callback_idx
                new_code.append(_I32_CONST)
                new_code.extend(write_signed(loc.line))
                new_code.append(_I32_CONST)
                new_code.extend(write_signed(loc.col))
                new_code.append(_CALL)
                new_code.extend(write_unsigned(callback_idx))
                last_line_col = lc

        opcode = code[i]
        new_code.append(opcode)
        i += 1

        # Handle immediates and shift function indices
        if opcode in _BLOCK_OPS:
            # blocktype: 0x40 (void), 0x7F/7E/7D/7C (valtype), or sleb128 (type index)
            bt = code[i]
            if bt == 0x40 or bt >= 0x7C:
                new_code.append(bt)
                i += 1
            else:
                val, i = read_signed(code, i)
                new_code.extend(write_signed(val))

        elif opcode == _CALL or opcode == _RETURN_CALL:
            func_idx, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(func_idx + func_idx_shift))

        elif opcode == _REF_FUNC:
            func_idx, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(func_idx + func_idx_shift))

        elif opcode == _CALL_INDIRECT:
            type_idx, i = read_unsigned(code, i)
            table_idx, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(type_idx))
            new_code.extend(write_unsigned(table_idx))

        elif opcode in _BR_OPS:
            label, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(label))

        elif opcode == _BR_TABLE:
            count, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(count))
            for _ in range(count + 1):  # count + default
                label, i = read_unsigned(code, i)
                new_code.extend(write_unsigned(label))

        elif opcode in _LOCAL_OPS or opcode in _GLOBAL_OPS:
            idx, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(idx))

        elif opcode == _I32_CONST:
            val, i = read_signed(code, i)
            new_code.extend(write_signed(val))

        elif opcode == _I64_CONST:
            val, i = read_signed(code, i)
            new_code.extend(write_signed(val))

        elif opcode == _F32_CONST:
            new_code.extend(code[i:i + 4])
            i += 4

        elif opcode == _F64_CONST:
            new_code.extend(code[i:i + 8])
            i += 8

        elif opcode in _MEMORY_OPS:
            align, i = read_unsigned(code, i)
            offset, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(align))
            new_code.extend(write_unsigned(offset))

        elif opcode in (_MEMORY_SIZE, _MEMORY_GROW):
            new_code.append(code[i])  # 0x00 memory index
            i += 1

        elif opcode == 0xFC:  # misc prefix (saturating truncation, etc.)
            sub_opcode, i = read_unsigned(code, i)
            new_code.extend(write_unsigned(sub_opcode))
            if sub_opcode <= 7:
                pass  # saturating truncation — no operands
            elif sub_opcode == 8:  # memory.init
                idx, i = read_unsigned(code, i)
                new_code.extend(write_unsigned(idx))
                new_code.append(code[i]); i += 1  # memory index byte
            elif sub_opcode == 9:  # data.drop
                idx, i = read_unsigned(code, i)
                new_code.extend(write_unsigned(idx))
            elif sub_opcode == 10:  # memory.copy
                new_code.append(code[i]); i += 1  # src memory
                new_code.append(code[i]); i += 1  # dst memory
            elif sub_opcode == 11:  # memory.fill
                new_code.append(code[i]); i += 1  # memory index
            elif sub_opcode >= 12:  # table ops
                idx, i = read_unsigned(code, i)
                new_code.extend(write_unsigned(idx))
                if sub_opcode in (12, 14):
                    idx2, i = read_unsigned(code, i)
                    new_code.extend(write_unsigned(idx2))

        # All other opcodes (arithmetic, comparison, drop, select, etc.) have no immediates

    return bytes(new_code)


# ---- Public API ----

def instrument_wasm(
    wasm_bytes: bytes,
    wasm_path: str | None = None,
    import_module: str = "env",
    import_name: str = "__on_source_line",
) -> tuple[bytes, list[SourceLoc]]:
    """Instrument a WASM binary with on_source_line(line, col) callbacks.

    Args:
        wasm_bytes: Raw WASM binary (must be compiled with -g for DWARF)
        wasm_path: Path to WASM file for llvm-dwarfdump. Auto-creates temp file if None.
        import_module: Module name for the callback import
        import_name: Function name for the callback import

    Returns:
        (instrumented_wasm_bytes, source_locations)
    """
    if wasm_path is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
        tmp.write(wasm_bytes)
        tmp.close()
        wasm_path = tmp.name

    # Parse DWARF
    locs = parse_dwarf_locations(wasm_path)
    if not locs:
        raise RuntimeError("No DWARF source locations found. Compile with -g.")

    # Deduplicate by (line, col) — keep first occurrence
    seen: set[tuple[int, int]] = set()
    unique_locs: list[SourceLoc] = []
    for loc in locs:
        key = (loc.line, loc.col)
        if key not in seen:
            seen.add(key)
            unique_locs.append(loc)

    # DWARF addresses are relative to the code section content start.
    # Compute each function's instruction range in that address space
    # from the ORIGINAL binary, before any modifications.
    content_offset = code_section_content_offset(wasm_bytes)
    body_ranges = decode_code_bodies_raw(wasm_bytes)

    mod = decode_module(wasm_bytes)

    # Find or add type (i32, i32) -> ()
    target = FuncType(params=(ValType.I32, ValType.I32), results=())
    for idx, ft in enumerate(mod.types):
        if ft.params == target.params and ft.results == target.results:
            type_idx = idx
            break
    else:
        mod.types.append(target)
        type_idx = len(mod.types) - 1

    # Prepend the callback import — all existing function indices shift by 1
    mod.imports.insert(0, Import(module=import_module, name=import_name, type_idx=type_idx))
    callback_idx = 0
    func_idx_shift = 1

    for exp in mod.exports:
        if exp.kind == ExportKind.FUNC:
            exp.index += func_idx_shift

    # Element sections pass through as raw bytes, indices unshifted —
    # hook WASM doesn't reference functions from tables.

    for body, (abs_start, _abs_end) in zip(mod.code, body_ranges):
        rel_start = abs_start - content_offset
        locs_at: dict[int, SourceLoc] = {}
        for loc in unique_locs:
            off = loc.address - rel_start
            if 0 <= off < len(body.code):
                locs_at[off] = loc
        body.code = _rewrite_code(body.code, callback_idx, locs_at, func_idx_shift)

    return encode_module(mod), unique_locs
