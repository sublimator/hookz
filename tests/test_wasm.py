"""Tests for hookz.wasm — decode, encode, roundtrip."""

import subprocess

import pytest

from hookz.wasm.types import Module, FuncType, SectionId, ExportKind, ValType
from hookz.wasm.decode import decode_module, decode_code_bodies_raw, DecodeError
from hookz.wasm.encode import encode_module


@pytest.fixture(scope="module")
def clean_balance_gate_wasm() -> bytes:
    """Compile and strip balance_gate.c → clean WASM bytes."""
    subprocess.run(
        ["uv", "run", "hookz", "debug-compile", "hooks/misc/balance_gate.c"],
        cwd="tests/e2e", capture_output=True, check=True,
    )
    subprocess.run(
        ["wasm-opt", "tests/e2e/hooks/misc/balance_gate.wasm",
         "--strip-debug", "--strip-producers", "--strip-target-features",
         "-o", "/tmp/test_clean_hook.wasm"],
        capture_output=True, check=True,
    )
    return open("/tmp/test_clean_hook.wasm", "rb").read()


@pytest.fixture(scope="module")
def debug_balance_gate_wasm() -> bytes:
    """Compile balance_gate.c with debug info (has custom sections)."""
    subprocess.run(
        ["uv", "run", "hookz", "debug-compile", "hooks/misc/balance_gate.c"],
        cwd="tests/e2e", capture_output=True, check=True,
    )
    return open("tests/e2e/hooks/misc/balance_gate.wasm", "rb").read()


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------

class TestDecodeModule:
    def test_too_short(self):
        with pytest.raises(DecodeError, match="too short"):
            decode_module(b"\x00\x61")

    def test_bad_magic(self):
        with pytest.raises(DecodeError, match="magic"):
            decode_module(b"\xFF" * 8)

    def test_finds_types(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert len(mod.types) > 0

    def test_finds_imports(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert len(mod.imports) > 0
        names = [i.name for i in mod.imports]
        assert "_g" in names
        assert "hook_account" in names
        assert all(i.module == "env" for i in mod.imports)

    def test_finds_exports(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert mod.hook_export is not None
        assert mod.hook_export.name == "hook"
        assert mod.hook_export.kind == ExportKind.FUNC

    def test_finds_cbak(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert mod.cbak_export is not None
        assert mod.cbak_export.name == "cbak"

    def test_finds_guard(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert mod.guard_func_idx is not None
        assert mod.guard_func_idx >= 0

    def test_finds_functions(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert len(mod.functions) > 0

    def test_finds_code(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert len(mod.code) > 0
        assert len(mod.code) == len(mod.functions)
        for body in mod.code:
            assert len(body.code) > 0
            assert body.code[-1] == 0x0B  # ends with end opcode

    def test_hook_type_signature(self, clean_balance_gate_wasm):
        """hook() should be int64_t(uint32_t)."""
        mod = decode_module(clean_balance_gate_wasm)
        hook_exp = mod.hook_export
        hook_type_idx = mod.func_type_idx(hook_exp.index)
        hook_type = mod.types[hook_type_idx]
        assert hook_type.is_hook_type

    def test_custom_sections_in_debug_build(self, debug_balance_gate_wasm):
        mod = decode_module(debug_balance_gate_wasm)
        assert len(mod.custom_sections) > 0

    def test_no_custom_sections_in_clean_build(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        assert len(mod.custom_sections) == 0


class TestDecodeCodeBodiesRaw:
    def test_finds_bodies(self, clean_balance_gate_wasm):
        bodies = decode_code_bodies_raw(clean_balance_gate_wasm)
        assert len(bodies) > 0
        for start, end in bodies:
            assert start < end
            assert end <= len(clean_balance_gate_wasm)


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------

class TestEncodeModule:
    def test_roundtrip_preserves_structure(self, clean_balance_gate_wasm):
        """Decode then encode should produce a valid module with same structure."""
        mod = decode_module(clean_balance_gate_wasm)
        out = encode_module(mod)

        # Re-decode the output
        mod2 = decode_module(out)

        # Same number of types, imports, functions, exports, code bodies
        assert len(mod2.types) == len(mod.types)
        assert len(mod2.imports) == len(mod.imports)
        assert len(mod2.functions) == len(mod.functions)
        assert len(mod2.exports) == len(mod.exports)
        assert len(mod2.code) == len(mod.code)

    def test_roundtrip_preserves_import_names(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        out = encode_module(mod)
        mod2 = decode_module(out)
        assert [i.name for i in mod2.imports] == [i.name for i in mod.imports]

    def test_roundtrip_preserves_export_names(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        out = encode_module(mod)
        mod2 = decode_module(out)
        assert [e.name for e in mod2.exports] == [e.name for e in mod.exports]

    def test_roundtrip_preserves_type_signatures(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        out = encode_module(mod)
        mod2 = decode_module(out)
        for t1, t2 in zip(mod.types, mod2.types):
            assert t1.params == t2.params
            assert t1.results == t2.results

    def test_output_starts_with_wasm_header(self, clean_balance_gate_wasm):
        mod = decode_module(clean_balance_gate_wasm)
        out = encode_module(mod)
        assert out[:8] == b"\x00\x61\x73\x6D\x01\x00\x00\x00"

    def test_empty_module(self):
        mod = Module()
        out = encode_module(mod)
        assert out == b"\x00\x61\x73\x6D\x01\x00\x00\x00"
