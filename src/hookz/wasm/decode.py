"""Decode WASM binary into hookz internal types.

Uses wasm-tob for section-level parsing, then converts to our own types.
Also provides raw byte offset tracking for the code section (needed by
the cleaner and guard checker which operate on raw bytes).
"""

from __future__ import annotations

import wasm_tob

from .leb128 import LEB128Error, read_unsigned
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
    RawSection,
    CustomSection,
)


class DecodeError(Exception):
    """Raised when WASM binary cannot be decoded."""


def decode_module(wasm: bytes) -> Module:
    """Decode a WASM binary into a Module.

    Args:
        wasm: Raw WASM binary bytes

    Returns:
        Module with all parsed sections

    Raises:
        DecodeError: If the binary is malformed
    """
    if len(wasm) < 8:
        raise DecodeError("WASM binary too short")
    if wasm[:8] != WASM_HEADER:
        raise DecodeError("Invalid WASM magic number or version")

    mod = Module()

    # Sections we pass through as raw bytes are extracted ourselves. The
    # DATA_COUNT, DATA, and ELEMENT sections are also stripped from the copy
    # handed to wasm-tob — it predates bulk memory and the newer element
    # encodings, and crashes on them.
    raw_dc = _extract_raw_section(wasm, SectionId.DATA_COUNT)
    if raw_dc is not None:
        mod.data_count, _ = read_unsigned(raw_dc.data, 0)

    for sec_id, target in (
        (SectionId.TABLE, mod.tables),
        (SectionId.MEMORY, mod.memories),
        (SectionId.GLOBAL, mod.globals),
        (SectionId.ELEMENT, mod.elements),
        (SectionId.DATA, mod.data),
    ):
        raw = _extract_raw_section(wasm, sec_id)
        if raw is not None:
            target.append(raw)

    wasm_for_tob = _strip_sections(
        wasm, {SectionId.DATA_COUNT, SectionId.DATA, SectionId.ELEMENT})

    for fragment in wasm_tob.decode_module(wasm_for_tob):
        sec_data = fragment.data
        if not hasattr(sec_data, 'id'):
            continue  # skip module header
        sec_id = sec_data.id

        if sec_id == SectionId.CUSTOM:
            name = bytes(sec_data.name).decode(errors="replace") if hasattr(sec_data, 'name') else ""
            payload = bytes(sec_data.payload) if hasattr(sec_data, 'payload') else b""
            mod.custom_sections.append(CustomSection(name=name, data=payload))

        elif sec_id == SectionId.TYPE:
            for entry in sec_data.payload.entries:
                params = tuple(_fix_valtype(p) for p in entry.param_types)
                # return_type is a single value (or None for void)
                if entry.return_count and entry.return_type is not None:
                    results = (_fix_valtype(entry.return_type),)
                else:
                    results = ()
                mod.types.append(FuncType(params=params, results=results))

        elif sec_id == SectionId.IMPORT:
            mod.imports, mod.other_imports = _decode_imports_raw(wasm)

        elif sec_id == SectionId.FUNCTION:
            mod.functions = list(sec_data.payload.types)

        elif sec_id == SectionId.EXPORT:
            for entry in sec_data.payload.entries:
                name = bytes(entry.field_str).decode()
                mod.exports.append(Export(
                    name=name,
                    kind=ExportKind(entry.kind),
                    index=entry.index,
                ))

        elif sec_id == SectionId.CODE:
            for body in sec_data.payload.bodies:
                locals_list = []
                for local in body.locals:
                    locals_list.append(LocalDecl(
                        count=local.count,
                        type=_fix_valtype(local.type),
                    ))
                mod.code.append(CodeBody(
                    locals=locals_list,
                    code=bytes(body.code),
                ))

        elif sec_id in (SectionId.TABLE, SectionId.MEMORY, SectionId.GLOBAL,
                        SectionId.START, SectionId.ELEMENT, SectionId.DATA):
            pass  # raw passthrough sections — extracted above the loop

    return mod


def _skip_limits(data: bytes, pos: int) -> int:
    """Skip a limits encoding (flags + min [+ max])."""
    flags = data[pos]
    pos += 1
    _, pos = read_unsigned(data, pos)  # min
    if flags & 0x01:
        _, pos = read_unsigned(data, pos)  # max
    return pos


def _decode_imports_raw(wasm: bytes) -> tuple[list[Import], list[bytes]]:
    """Walk the raw import section.

    Returns (function imports parsed, non-function import entries as raw
    bytes). Raw entries are preserved so encode can re-emit them — function
    index math elsewhere counts only function imports.
    """
    section = _extract_raw_section(wasm, SectionId.IMPORT)
    if section is None:
        return [], []
    data = section.data
    imports: list[Import] = []
    other: list[bytes] = []
    try:
        count, pos = read_unsigned(data, 0)
        for _ in range(count):
            start = pos
            mod_len, pos = read_unsigned(data, pos)
            module = data[pos:pos + mod_len].decode(errors="replace")
            pos += mod_len
            name_len, pos = read_unsigned(data, pos)
            name = data[pos:pos + name_len].decode(errors="replace")
            pos += name_len
            kind = data[pos]
            pos += 1
            if kind == 0x00:  # function
                type_idx, pos = read_unsigned(data, pos)
                imports.append(Import(module=module, name=name, type_idx=type_idx))
            elif kind == 0x01:  # table: reftype + limits
                pos += 1
                pos = _skip_limits(data, pos)
                other.append(data[start:pos])
            elif kind == 0x02:  # memory: limits
                pos = _skip_limits(data, pos)
                other.append(data[start:pos])
            elif kind == 0x03:  # global: valtype + mutability
                pos += 2
                other.append(data[start:pos])
            else:
                raise DecodeError(f"Unknown import kind {kind}")
    except (LEB128Error, IndexError) as e:
        raise DecodeError(f"Malformed import section: {e}") from e
    return imports, other


def code_section_content_offset(wasm: bytes) -> int:
    """File offset of the code section's content (after section id + size).

    DWARF line-table addresses in WASM binaries are relative to this point.
    """
    i = 8  # skip header
    try:
        while i < len(wasm):
            section_type = wasm[i]
            i += 1
            section_length, i = read_unsigned(wasm, i)
            if section_type == SectionId.CODE:
                return i
            i += section_length
    except LEB128Error as e:
        raise DecodeError(f"Malformed section header: {e}") from e
    raise DecodeError("No code section found")


def decode_code_bodies_raw(wasm: bytes) -> list[tuple[int, int]]:
    """Find raw byte offsets of code bodies in the WASM binary.

    Returns list of (start_offset, end_offset) for each function body's
    instructions (after locals have been skipped).

    This is needed by the guard checker and cleaner which operate on
    raw bytes rather than parsed structures.
    """
    i = 8  # skip header
    try:
        while i < len(wasm):
            section_type = wasm[i]
            i += 1
            section_length, i = read_unsigned(wasm, i)
            next_section = i + section_length

            if section_type == SectionId.CODE:
                func_count, i = read_unsigned(wasm, i)
                bodies = []
                for _ in range(func_count):
                    code_size, i = read_unsigned(wasm, i)
                    code_end = i + code_size

                    # Skip locals
                    local_count, i = read_unsigned(wasm, i)
                    for _ in range(local_count):
                        _, i = read_unsigned(wasm, i)  # count
                        i += 1  # type

                    bodies.append((i, code_end))
                    i = code_end
                return bodies

            i = next_section
    except LEB128Error as e:
        raise DecodeError(f"LEB128 overflow/truncated: {e}") from e

    raise DecodeError("No code section found")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fix_valtype(v: int) -> int:
    """Convert wasm-tob's negative val types to standard WASM encoding.

    wasm-tob uses: -1=i32, -2=i64, -3=f32, -4=f64, -5=v128
    WASM uses:    0x7F=i32, 0x7E=i64, 0x7D=f32, 0x7C=f64, 0x7B=v128
    """
    mapping = {-1: 0x7F, -2: 0x7E, -3: 0x7D, -4: 0x7C, -5: 0x7B}
    return mapping.get(v, v)


def _strip_sections(wasm: bytes, target_ids: set[int]) -> bytes:
    """Return a copy of the binary with all sections in target_ids removed."""
    out = bytearray(wasm[:8])
    i = 8
    try:
        while i < len(wasm):
            start = i
            sec_id = wasm[i]
            i += 1
            sec_len, i = read_unsigned(wasm, i)
            end = i + sec_len
            if sec_id not in target_ids:
                out.extend(wasm[start:end])
            i = end
    except LEB128Error as e:
        raise DecodeError(f"Malformed section header: {e}") from e
    return bytes(out)


def _extract_raw_section(wasm: bytes, target_id: int) -> RawSection | None:
    """Extract the raw bytes of a section by ID."""
    i = 8
    while i < len(wasm):
        sec_id = wasm[i]
        i += 1
        sec_len, i = read_unsigned(wasm, i)
        if sec_id == target_id:
            return RawSection(id=SectionId(sec_id), data=wasm[i:i + sec_len])
        i += sec_len
    return None
