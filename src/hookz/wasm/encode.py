"""Encode hookz Module back to WASM binary.

Handles LEB128 encoding, section headers, and all the byte-level details
of producing a valid WASM binary from our internal types.
"""

from __future__ import annotations

from .leb128 import write_signed, write_unsigned
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


def _encode_string(s: str) -> bytes:
    """Encode a string as length-prefixed UTF-8."""
    encoded = s.encode("utf-8")
    return write_unsigned(len(encoded)) + encoded


# ---------------------------------------------------------------------------
# Section encoding
# ---------------------------------------------------------------------------

def _encode_section(section_id: int, payload: bytes) -> bytes:
    """Wrap a payload in a section header (id + length)."""
    return bytes([section_id]) + write_unsigned(len(payload)) + payload


def _encode_type_section(types: list[FuncType]) -> bytes:
    """Encode the type section."""
    payload = bytearray()
    payload.extend(write_unsigned(len(types)))
    for ft in types:
        payload.append(0x60)  # functype marker
        payload.extend(write_unsigned(len(ft.params)))
        for p in ft.params:
            payload.extend(write_unsigned(p))
        payload.extend(write_unsigned(len(ft.results)))
        for r in ft.results:
            payload.extend(write_unsigned(r))
    return _encode_section(SectionId.TYPE, bytes(payload))


def _encode_import_section(imports: list[Import], other_imports: list[bytes]) -> bytes:
    """Encode the import section: function imports, then raw non-function entries."""
    payload = bytearray()
    payload.extend(write_unsigned(len(imports) + len(other_imports)))
    for imp in imports:
        payload.extend(_encode_string(imp.module))
        payload.extend(_encode_string(imp.name))
        payload.append(0x00)  # function import kind
        payload.extend(write_unsigned(imp.type_idx))
    for raw in other_imports:
        payload.extend(raw)
    return _encode_section(SectionId.IMPORT, bytes(payload))


def _encode_function_section(type_indices: list[int]) -> bytes:
    """Encode the function section (maps defined funcs to type indices)."""
    payload = bytearray()
    payload.extend(write_unsigned(len(type_indices)))
    for idx in type_indices:
        payload.extend(write_unsigned(idx))
    return _encode_section(SectionId.FUNCTION, bytes(payload))


def _encode_export_section(exports: list[Export]) -> bytes:
    """Encode the export section."""
    payload = bytearray()
    payload.extend(write_unsigned(len(exports)))
    for exp in exports:
        payload.extend(_encode_string(exp.name))
        payload.append(exp.kind)
        payload.extend(write_unsigned(exp.index))
    return _encode_section(SectionId.EXPORT, bytes(payload))


def _encode_code_section(bodies: list[CodeBody]) -> bytes:
    """Encode the code section."""
    payload = bytearray()
    payload.extend(write_unsigned(len(bodies)))
    for body in bodies:
        # Encode function body: locals + code
        func_body = bytearray()
        func_body.extend(write_unsigned(len(body.locals)))
        for local in body.locals:
            func_body.extend(write_unsigned(local.count))
            func_body.append(local.type)
        func_body.extend(body.code)
        # Prefix with body size
        payload.extend(write_unsigned(len(func_body)))
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
    if mod.imports or mod.other_imports:
        out.extend(_encode_import_section(mod.imports, mod.other_imports))

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

    # 9.5 Data count section — must precede code per spec
    if mod.data_count is not None:
        out.extend(_encode_section(SectionId.DATA_COUNT, bytes(write_unsigned(mod.data_count))))

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
        payload.extend(write_unsigned(len(name_bytes)))
        payload.extend(name_bytes)
        payload.extend(cs.data)
        out.extend(_encode_section(0, bytes(payload)))

    return bytes(out)
