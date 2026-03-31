"""WASM binary rewriter — inject on_source_line(line, col) callbacks.

Parses the WASM binary, reads DWARF .debug_line to get bytecode→source mapping,
then injects a host function call at every new source location.

WASM's structured control flow means inserting instructions never breaks branches
(they use nesting depth, not byte offsets). We only need to:
1. Add __on_source_line as a new import (and its type if needed)
2. Shift all existing call/ref.func function indices by 1
3. Insert i32.const line; i32.const col; call $idx at each DWARF line boundary
4. Update section and function body sizes

TODO: Refactor to use hookz.wasm.types/decode/encode instead of the
inline LEB128/section parsing code below. The hookz.wasm package now
provides all of this. Dependency direction: hookz.coverage → hookz.wasm.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass
from pathlib import Path


# ---- LEB128 encoding/decoding ----

def _decode_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset


def _encode_uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            break
    return bytes(out)


def _decode_sleb128(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            if shift < 64 and (byte & 0x40):
                result |= -(1 << shift)
            break
    return result, offset


def _encode_sleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40)):
            out.append(byte)
            break
        out.append(byte | 0x80)
    return bytes(out)


# ---- DWARF source locations ----

@dataclass
class SourceLoc:
    address: int  # bytecode offset relative to code section body
    line: int
    col: int


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
    r = subprocess.run(
        ["xcrun", "llvm-dwarfdump", "--debug-line", wasm_path],
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


# ---- WASM section parsing ----

@dataclass
class WasmSection:
    id: int
    data: bytes


def _parse_sections(data: bytes) -> tuple[bytes, list[WasmSection]]:
    """Parse WASM binary into header + sections."""
    header = data[:8]  # magic + version
    sections: list[WasmSection] = []
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        size, offset = _decode_uleb128(data, offset)
        section_data = data[offset:offset + size]
        sections.append(WasmSection(id=section_id, data=section_data))
        offset += size
    return header, sections


def _rebuild_wasm(header: bytes, sections: list[WasmSection]) -> bytes:
    """Reassemble WASM binary from header + sections."""
    out = bytearray(header)
    for s in sections:
        out.append(s.id)
        out.extend(_encode_uleb128(len(s.data)))
        out.extend(s.data)
    return bytes(out)


# ---- Type section manipulation ----

def _find_or_add_void_ii_type(sections: list[WasmSection]) -> int:
    """Find or add type (i32, i32) -> () in the type section. Returns type index."""
    # Target: functype 0x60, params [0x7F, 0x7F], results []
    target_type = bytes([0x60, 0x02, 0x7F, 0x7F, 0x00])

    for s in sections:
        if s.id == 1:  # Type section
            data = s.data
            count, pos = _decode_uleb128(data, 0)
            idx = 0
            for _ in range(count):
                start = pos
                if data[pos] != 0x60:
                    break
                pos += 1
                param_count, pos = _decode_uleb128(data, pos)
                pos += param_count
                result_count, pos = _decode_uleb128(data, pos)
                pos += result_count
                entry = data[start:pos]
                if entry == target_type:
                    return idx
                idx += 1

            # Not found — append it
            new_data = bytearray()
            new_data.extend(_encode_uleb128(count + 1))
            new_data.extend(data[len(_encode_uleb128(count)):])
            new_data.extend(target_type)
            s.data = bytes(new_data)
            return count

    raise RuntimeError("No type section found")


# ---- Import section manipulation ----

def _count_func_imports(sections: list[WasmSection]) -> int:
    """Count function imports in the import section."""
    for s in sections:
        if s.id == 2:
            data = s.data
            count, pos = _decode_uleb128(data, 0)
            func_count = 0
            for _ in range(count):
                # module name
                mod_len, pos = _decode_uleb128(data, pos)
                pos += mod_len
                # field name
                field_len, pos = _decode_uleb128(data, pos)
                pos += field_len
                # import kind
                kind = data[pos]
                pos += 1
                if kind == 0x00:  # func
                    _, pos = _decode_uleb128(data, pos)
                    func_count += 1
                elif kind == 0x01:  # table
                    pos += 1  # reftype
                    _, pos = _decode_uleb128(data, pos)  # flags
                    _, pos = _decode_uleb128(data, pos)  # initial
                    # TODO: handle max
                elif kind == 0x02:  # memory
                    _, pos = _decode_uleb128(data, pos)
                    _, pos = _decode_uleb128(data, pos)
                elif kind == 0x03:  # global
                    pos += 1  # valtype
                    pos += 1  # mutability
            return func_count
    return 0


def _add_func_import(sections: list[WasmSection], module: str, name: str, type_idx: int) -> int:
    """Add a function import at the START of imports. Returns index 0.

    All existing function indices shift by 1.
    """
    for s in sections:
        if s.id == 2:
            data = s.data
            count, pos = _decode_uleb128(data, 0)
            rest = data[pos:]  # everything after the count

            # Build the new import entry
            entry = bytearray()
            mod_bytes = module.encode()
            entry.extend(_encode_uleb128(len(mod_bytes)))
            entry.extend(mod_bytes)
            name_bytes = name.encode()
            entry.extend(_encode_uleb128(len(name_bytes)))
            entry.extend(name_bytes)
            entry.append(0x00)  # func import
            entry.extend(_encode_uleb128(type_idx))

            # Prepend before existing imports
            new_data = bytearray()
            new_data.extend(_encode_uleb128(count + 1))
            new_data.extend(entry)
            new_data.extend(rest)
            s.data = bytes(new_data)

            return 0  # our import is now function index 0

    raise RuntimeError("No import section found")


# ---- Code section instrumentation ----

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
_MEMORY_OPS = set(range(0x28, 0x3F + 1))  # loads/stores — uleb128 align + uleb128 offset
_MEMORY_SIZE = 0x3F
_MEMORY_GROW = 0x40
_BR_TABLE = 0x0E  # uleb128 count + uleb128[] + uleb128 default


def _rewrite_function_body(
    body: bytes,
    body_offset_in_section: int,
    callback_idx: int,
    locs: list[SourceLoc],
    func_idx_shift: int,
) -> bytes:
    """Rewrite a single function body: shift call indices and insert callbacks.

    body_offset_in_section: offset of this function body within the code
    section content (i.e. relative to code section content start, which
    is the same base that DWARF addresses use).
    """
    # Parse locals
    pos = 0
    local_decl_count, pos = _decode_uleb128(body, pos)
    for _ in range(local_decl_count):
        _, pos = _decode_uleb128(body, pos)  # count
        pos += 1  # valtype

    locals_prefix = body[:pos]
    code = body[pos:]

    # DWARF addresses are relative to code section content start.
    # The first instruction of this function's code is at:
    #   dwarf_addr = body_offset_in_section + len(locals_prefix)
    code_dwarf_start = body_offset_in_section + len(locals_prefix)

    addr_to_loc: dict[int, SourceLoc] = {}
    for loc in locs:
        code_offset = loc.address - code_dwarf_start
        if 0 <= code_offset < len(code):
            addr_to_loc[code_offset] = loc

    # Walk through instructions, building new code
    new_code = bytearray()
    last_line_col: tuple[int, int] | None = None
    i = 0

    while i < len(code):
        # Check if this offset has a DWARF entry (new source location)
        if i in addr_to_loc:
            loc = addr_to_loc[i]
            lc = (loc.line, loc.col)
            if lc != last_line_col:
                # Insert: i32.const line; i32.const col; call callback_idx
                new_code.append(_I32_CONST)
                new_code.extend(_encode_sleb128(loc.line))
                new_code.append(_I32_CONST)
                new_code.extend(_encode_sleb128(loc.col))
                new_code.append(_CALL)
                new_code.extend(_encode_uleb128(callback_idx))
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
                val, i = _decode_sleb128(code, i)
                new_code.extend(_encode_sleb128(val))

        elif opcode == _CALL or opcode == _RETURN_CALL:
            func_idx, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(func_idx + func_idx_shift))

        elif opcode == _REF_FUNC:
            func_idx, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(func_idx + func_idx_shift))

        elif opcode == _CALL_INDIRECT:
            type_idx, i = _decode_uleb128(code, i)
            table_idx, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(type_idx))
            new_code.extend(_encode_uleb128(table_idx))

        elif opcode in _BR_OPS:
            label, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(label))

        elif opcode == _BR_TABLE:
            count, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(count))
            for _ in range(count + 1):  # count + default
                label, i = _decode_uleb128(code, i)
                new_code.extend(_encode_uleb128(label))

        elif opcode in _LOCAL_OPS or opcode in _GLOBAL_OPS:
            idx, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(idx))

        elif opcode == _I32_CONST:
            val, i = _decode_sleb128(code, i)
            new_code.extend(_encode_sleb128(val))

        elif opcode == _I64_CONST:
            val, i = _decode_sleb128(code, i)
            new_code.extend(_encode_sleb128(val))

        elif opcode == _F32_CONST:
            new_code.extend(code[i:i + 4])
            i += 4

        elif opcode == _F64_CONST:
            new_code.extend(code[i:i + 8])
            i += 8

        elif opcode in _MEMORY_OPS:
            align, i = _decode_uleb128(code, i)
            offset, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(align))
            new_code.extend(_encode_uleb128(offset))

        elif opcode in (_MEMORY_SIZE, _MEMORY_GROW):
            new_code.append(code[i])  # 0x00 memory index
            i += 1

        elif opcode == 0xFC:  # misc prefix (saturating truncation, etc.)
            sub_opcode, i = _decode_uleb128(code, i)
            new_code.extend(_encode_uleb128(sub_opcode))
            # memory.init, data.drop, memory.copy, memory.fill, table ops
            if sub_opcode <= 7:  # memory/data ops
                idx, i = _decode_uleb128(code, i)
                new_code.extend(_encode_uleb128(idx))
                if sub_opcode in (8, 10):  # memory.init, memory.copy
                    new_code.append(code[i])
                    i += 1
            elif sub_opcode >= 12:  # table ops
                idx, i = _decode_uleb128(code, i)
                new_code.extend(_encode_uleb128(idx))
                if sub_opcode in (12, 14):
                    idx2, i = _decode_uleb128(code, i)
                    new_code.extend(_encode_uleb128(idx2))

        # All other opcodes (arithmetic, comparison, drop, select, etc.) have no immediates

    return locals_prefix + bytes(new_code)


def _instrument_code_section(
    sections: list[WasmSection],
    callback_idx: int,
    locs: list[SourceLoc],
    func_idx_shift: int,
    code_section_file_offset: int = 0,
) -> None:
    """Rewrite all function bodies in the code section."""
    for s in sections:
        if s.id != 10:
            continue

        data = s.data
        pos = 0
        func_count, pos = _decode_uleb128(data, pos)

        new_bodies = bytearray()
        new_bodies.extend(_encode_uleb128(func_count))

        for _ in range(func_count):
            body_size, pos = _decode_uleb128(data, pos)
            body = data[pos:pos + body_size]

            # Offset of this body within the code section content
            body_offset_in_section = pos

            new_body = _rewrite_function_body(
                body, body_offset_in_section, callback_idx, locs, func_idx_shift,
            )

            new_bodies.extend(_encode_uleb128(len(new_body)))
            new_bodies.extend(new_body)
            pos += body_size

        s.data = bytes(new_bodies)


def _shift_exports(sections: list[WasmSection], shift: int) -> None:
    """Shift function indices in the export section."""
    for s in sections:
        if s.id != 7:
            continue
        data = s.data
        pos = 0
        count, pos = _decode_uleb128(data, 0)

        new_data = bytearray(_encode_uleb128(count))
        for _ in range(count):
            name_len, pos = _decode_uleb128(data, pos)
            name = data[pos:pos + name_len]
            pos += name_len
            kind = data[pos]
            pos += 1
            idx, pos = _decode_uleb128(data, pos)

            new_data.extend(_encode_uleb128(name_len))
            new_data.extend(name)
            new_data.append(kind)
            if kind == 0x00:  # func export
                new_data.extend(_encode_uleb128(idx + shift))
            else:
                new_data.extend(_encode_uleb128(idx))

        s.data = bytes(new_data)


def _shift_function_section(sections: list[WasmSection]) -> None:
    """No shift needed — function section maps to type indices, not func indices."""
    pass


def _shift_elements(sections: list[WasmSection], shift: int) -> None:
    """Shift function indices in element sections (table init)."""
    for s in sections:
        if s.id != 9:
            continue
        # Element section rewriting is complex — skip for PoC
        # Hook WASM typically doesn't use tables heavily
        pass


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

    # Calculate the code section content offset in the ORIGINAL binary
    # DWARF addresses are relative to this. Must be computed before any modifications.
    code_section_file_offset = 0
    offset = 8  # magic + version
    orig_data = wasm_bytes
    while offset < len(orig_data):
        section_id = orig_data[offset]
        offset += 1
        size, offset = _decode_uleb128(orig_data, offset)
        if section_id == 10:  # Code section
            code_section_file_offset = offset
            break
        offset += size

    # Parse WASM into mutable sections
    header, sections = _parse_sections(wasm_bytes)

    # Add type for (i32, i32) -> ()
    type_idx = _find_or_add_void_ii_type(sections)

    # Add import — this shifts all function indices by 1
    callback_idx = _add_func_import(sections, import_module, import_name, type_idx)
    func_idx_shift = 1

    # Shift exports
    _shift_exports(sections, func_idx_shift)

    # Shift element section
    _shift_elements(sections, func_idx_shift)

    # DWARF addresses are relative to the code section content start (after
    # the section ID + size bytes). Pass the file offset of the code section
    # content so the instrumenter can compute the right offsets.
    _instrument_code_section(
        sections, callback_idx, unique_locs, func_idx_shift,
        code_section_file_offset,
    )

    # Reassemble
    result = _rebuild_wasm(header, sections)
    return result, unique_locs
