"""Internal types for WASM module representation.

These are hookz's own types — not tied to wasm-tob or any other library.
The decode module converts from wasm-tob's types to these, and the encode
module serializes these back to binary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


# ---------------------------------------------------------------------------
# WASM constants
# ---------------------------------------------------------------------------

WASM_MAGIC = b"\x00\x61\x73\x6D"
WASM_VERSION = b"\x01\x00\x00\x00"
WASM_HEADER = WASM_MAGIC + WASM_VERSION


class SectionId(IntEnum):
    CUSTOM = 0
    TYPE = 1
    IMPORT = 2
    FUNCTION = 3
    TABLE = 4
    MEMORY = 5
    GLOBAL = 6
    EXPORT = 7
    START = 8
    ELEMENT = 9
    CODE = 10
    DATA = 11
    DATA_COUNT = 12


class ExportKind(IntEnum):
    FUNC = 0
    TABLE = 1
    MEMORY = 2
    GLOBAL = 3


class ValType(IntEnum):
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C
    V128 = 0x7B
    FUNCREF = 0x70
    EXTERNREF = 0x6F


# Hook entry point signature: int64_t hook(uint32_t)
HOOK_PARAM_TYPES = (ValType.I32,)
HOOK_RETURN_TYPE = ValType.I64


# ---------------------------------------------------------------------------
# Module types
# ---------------------------------------------------------------------------

@dataclass
class FuncType:
    """Function type signature."""
    params: tuple[int, ...]  # ValType values
    results: tuple[int, ...]  # ValType values

    @property
    def is_hook_type(self) -> bool:
        """Matches int64_t (*)(uint32_t)?"""
        return self.params == HOOK_PARAM_TYPES and self.results == (HOOK_RETURN_TYPE,)


@dataclass
class Import:
    """Function import from host environment."""
    module: str
    name: str
    type_idx: int


@dataclass
class Export:
    """Module export."""
    name: str
    kind: ExportKind
    index: int


@dataclass
class LocalDecl:
    """Local variable declaration in a function body."""
    count: int
    type: int  # ValType


@dataclass
class CodeBody:
    """Function body (locals + raw bytecode)."""
    locals: list[LocalDecl]
    code: bytes  # raw instruction bytes (including final 0x0B end)

    @property
    def code_without_end(self) -> bytes:
        """Instructions without the trailing end opcode."""
        if self.code and self.code[-1] == 0x0B:
            return self.code[:-1]
        return self.code


@dataclass
class RawSection:
    """A section we don't fully parse — just store raw bytes."""
    id: SectionId
    data: bytes


@dataclass
class CustomSection:
    """Custom section with name."""
    name: str
    data: bytes


@dataclass
class Module:
    """Parsed WASM module — hookz internal representation.

    All fields are optional because a module may not have every section.
    The order of sections matters for serialization.
    """
    types: list[FuncType] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    functions: list[int] = field(default_factory=list)  # type indices
    tables: list[RawSection] = field(default_factory=list)
    memories: list[RawSection] = field(default_factory=list)
    globals: list[RawSection] = field(default_factory=list)
    exports: list[Export] = field(default_factory=list)
    start: int | None = None
    elements: list[RawSection] = field(default_factory=list)
    code: list[CodeBody] = field(default_factory=list)
    data: list[RawSection] = field(default_factory=list)
    data_count: int | None = None
    custom_sections: list[CustomSection] = field(default_factory=list)

    # --- Computed properties ---

    @property
    def import_count(self) -> int:
        return len(self.imports)

    @property
    def func_count(self) -> int:
        """Total function count (imports + defined)."""
        return self.import_count + len(self.functions)

    def func_type_idx(self, func_idx: int) -> int:
        """Get type index for a function (import or defined)."""
        if func_idx < self.import_count:
            return self.imports[func_idx].type_idx
        return self.functions[func_idx - self.import_count]

    def find_import(self, name: str) -> int | None:
        """Find import function index by name. Returns None if not found."""
        for i, imp in enumerate(self.imports):
            if imp.name == name:
                return i
        return None

    def find_export(self, name: str) -> Export | None:
        """Find export by name."""
        for exp in self.exports:
            if exp.name == name:
                return exp
        return None

    @property
    def hook_export(self) -> Export | None:
        return self.find_export("hook")

    @property
    def cbak_export(self) -> Export | None:
        return self.find_export("cbak")

    @property
    def guard_func_idx(self) -> int | None:
        return self.find_import("_g")
