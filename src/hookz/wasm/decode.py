"""Decode WASM binary into hookz internal types.

Uses wasm-tob for section-level parsing, then converts to our own types.
Also provides raw byte offset tracking for the code section (needed by
the cleaner and guard checker which operate on raw bytes).
"""

from __future__ import annotations

import wasm_tob

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

    for fragment in wasm_tob.decode_module(wasm):
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
            for entry in sec_data.payload.entries:
                module = bytes(entry.module_str).decode()
                name = bytes(entry.field_str).decode()
                if entry.kind == 0:  # function import
                    # FunctionImportEntryData has a .type field (VarUInt32)
                    type_idx = entry.type.type
                    mod.imports.append(Import(module=module, name=name, type_idx=type_idx))
                # Skip non-function imports for now (table, memory, global)

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
                        SectionId.START, SectionId.ELEMENT, SectionId.DATA,
                        SectionId.DATA_COUNT):
            # Store as raw section — we'll copy these through unchanged
            raw = _extract_raw_section(wasm, sec_id)
            if raw is not None:
                if sec_id == SectionId.TABLE:
                    mod.tables.append(raw)
                elif sec_id == SectionId.MEMORY:
                    mod.memories.append(raw)
                elif sec_id == SectionId.GLOBAL:
                    mod.globals.append(raw)
                elif sec_id == SectionId.ELEMENT:
                    mod.elements.append(raw)
                elif sec_id == SectionId.DATA:
                    mod.data.append(raw)
                elif sec_id == SectionId.DATA_COUNT:
                    mod.data.append(raw)  # treat as raw data
                elif sec_id == SectionId.START:
                    pass  # TODO: parse start section

    return mod


def decode_code_bodies_raw(wasm: bytes) -> list[tuple[int, int]]:
    """Find raw byte offsets of code bodies in the WASM binary.

    Returns list of (start_offset, end_offset) for each function body's
    instructions (after locals have been skipped).

    This is needed by the guard checker and cleaner which operate on
    raw bytes rather than parsed structures.
    """
    i = 8  # skip header
    while i < len(wasm):
        section_type = wasm[i]
        i += 1
        section_length, i = _leb128(wasm, i)
        next_section = i + section_length

        if section_type == SectionId.CODE:
            func_count, i = _leb128(wasm, i)
            bodies = []
            for _ in range(func_count):
                code_size, i = _leb128(wasm, i)
                code_end = i + code_size

                # Skip locals
                local_count, i = _leb128(wasm, i)
                for _ in range(local_count):
                    _, i = _leb128(wasm, i)  # count
                    i += 1  # type

                bodies.append((i, code_end))
                i = code_end
            return bodies

        i = next_section

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


def _extract_raw_section(wasm: bytes, target_id: int) -> RawSection | None:
    """Extract the raw bytes of a section by ID."""
    i = 8
    while i < len(wasm):
        sec_id = wasm[i]
        i += 1
        sec_len, i = _leb128(wasm, i)
        if sec_id == target_id:
            return RawSection(id=SectionId(sec_id), data=wasm[i:i + sec_len])
        i += sec_len
    return None


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
            raise DecodeError("LEB128 overflow")
    raise DecodeError("LEB128 truncated")
