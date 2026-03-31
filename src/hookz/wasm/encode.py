"""Encode hookz Module back to WASM binary.

Handles LEB128 encoding, section headers, and all the byte-level details
of producing a valid WASM binary from our internal types.
"""

from __future__ import annotations

from .types import (
    WASM_HEADER,
    SectionId,
    ExportKind,
    Module,
    FuncType,
    Import,
    Export,
    CodeBody,
    RawSection,
)


class EncodeError(Exception):
    """Raised when a Module cannot be serialized."""


# ---------------------------------------------------------------------------
# LEB128 encoding
# ---------------------------------------------------------------------------

def _encode_leb128(value: int) -> bytes:
    """Encode unsigned integer as LEB128."""
    if value < 0:
        raise EncodeError(f"Cannot encode negative value {value} as unsigned LEB128")
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def _encode_signed_leb128(value: int) -> bytes:
    """Encode signed integer as signed LEB128."""
    result = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


def _encode_string(s: str) -> bytes:
    """Encode a string as length-prefixed UTF-8."""
    encoded = s.encode("utf-8")
    return _encode_leb128(len(encoded)) + encoded


# ---------------------------------------------------------------------------
# Section encoding
# ---------------------------------------------------------------------------

def _encode_section(section_id: int, payload: bytes) -> bytes:
    """Wrap a payload in a section header (id + length)."""
    return bytes([section_id]) + _encode_leb128(len(payload)) + payload


def _encode_type_section(types: list[FuncType]) -> bytes:
    """Encode the type section."""
    payload = bytearray()
    payload.extend(_encode_leb128(len(types)))
    for ft in types:
        payload.append(0x60)  # functype marker
        payload.extend(_encode_leb128(len(ft.params)))
        for p in ft.params:
            payload.extend(_encode_leb128(p))
        payload.extend(_encode_leb128(len(ft.results)))
        for r in ft.results:
            payload.extend(_encode_leb128(r))
    return _encode_section(SectionId.TYPE, bytes(payload))


def _encode_import_section(imports: list[Import]) -> bytes:
    """Encode the import section (function imports only)."""
    payload = bytearray()
    payload.extend(_encode_leb128(len(imports)))
    for imp in imports:
        payload.extend(_encode_string(imp.module))
        payload.extend(_encode_string(imp.name))
        payload.append(0x00)  # function import kind
        payload.extend(_encode_leb128(imp.type_idx))
    return _encode_section(SectionId.IMPORT, bytes(payload))


def _encode_function_section(type_indices: list[int]) -> bytes:
    """Encode the function section (maps defined funcs to type indices)."""
    payload = bytearray()
    payload.extend(_encode_leb128(len(type_indices)))
    for idx in type_indices:
        payload.extend(_encode_leb128(idx))
    return _encode_section(SectionId.FUNCTION, bytes(payload))


def _encode_export_section(exports: list[Export]) -> bytes:
    """Encode the export section."""
    payload = bytearray()
    payload.extend(_encode_leb128(len(exports)))
    for exp in exports:
        payload.extend(_encode_string(exp.name))
        payload.append(exp.kind)
        payload.extend(_encode_leb128(exp.index))
    return _encode_section(SectionId.EXPORT, bytes(payload))


def _encode_code_section(bodies: list[CodeBody]) -> bytes:
    """Encode the code section."""
    payload = bytearray()
    payload.extend(_encode_leb128(len(bodies)))
    for body in bodies:
        # Encode function body: locals + code
        func_body = bytearray()
        func_body.extend(_encode_leb128(len(body.locals)))
        for local in body.locals:
            func_body.extend(_encode_leb128(local.count))
            func_body.append(local.type)
        func_body.extend(body.code)
        # Prefix with body size
        payload.extend(_encode_leb128(len(func_body)))
        payload.extend(func_body)
    return _encode_section(SectionId.CODE, bytes(payload))


def _encode_raw_section(section: RawSection) -> bytes:
    """Encode a raw section (just id + length + data)."""
    return _encode_section(section.id, section.data)


# ---------------------------------------------------------------------------
# Module encoding
# ---------------------------------------------------------------------------

def encode_module(mod: Module) -> bytes:
    """Encode a Module to WASM binary.

    Sections are written in the order required by the WASM spec:
    type, import, function, table, memory, global, export, start,
    element, data_count, code, data.

    Custom sections are included if present on the Module.
    """
    out = bytearray(WASM_HEADER)

    # 1. Type section
    if mod.types:
        out.extend(_encode_type_section(mod.types))

    # 2. Import section
    if mod.imports:
        out.extend(_encode_import_section(mod.imports))

    # 3. Function section
    if mod.functions:
        out.extend(_encode_function_section(mod.functions))

    # 4. Table section(s)
    for sec in mod.tables:
        out.extend(_encode_raw_section(sec))

    # 5. Memory section(s)
    for sec in mod.memories:
        out.extend(_encode_raw_section(sec))

    # 6. Global section(s)
    for sec in mod.globals:
        out.extend(_encode_raw_section(sec))

    # 7. Export section
    if mod.exports:
        out.extend(_encode_export_section(mod.exports))

    # 8. Start section — hooks don't use it, skip

    # 9. Element section(s)
    for sec in mod.elements:
        out.extend(_encode_raw_section(sec))

    # 10. Code section
    if mod.code:
        out.extend(_encode_code_section(mod.code))

    # 11. Data section(s)
    for sec in mod.data:
        out.extend(_encode_raw_section(sec))

    # Custom sections (appended at end — valid per WASM spec)
    for cs in mod.custom_sections:
        payload = bytearray()
        name_bytes = cs.name.encode("utf-8")
        payload.extend(_encode_leb128(len(name_bytes)))
        payload.extend(name_bytes)
        payload.extend(cs.data)
        out.extend(_encode_section(0, bytes(payload)))

    return bytes(out)
