"""Tests for the hook API whitelist parsed from xahaud's hook_api.macro.

The whitelist is what the guard checker validates imports against, so it has
to agree with xahaud's own getImportWhitelist() exactly — both the set of
names and the wasm type codes of every signature.

hook_api.macro is a list of macro invocations rather than a translation unit,
so whitelist.py normalises it into valid C (emulating the same #define
substitutions Enum.h applies) and then parses it with tree-sitter.
"""

import pytest

from hookz.wasm.whitelist import (
    COVERAGE_IMPORT,
    COVERAGE_SIGNATURE,
    VOID,
    WASM_TYPE_CODE,
    HookApiFunction,
    derive_amendments,
    get_import_signatures,
    get_whitelist,
    load_from_config,
    parse_hook_api_macro,
)


@pytest.fixture(scope="module")
def functions() -> list[HookApiFunction]:
    return load_from_config()


class TestMacroParsing:
    def test_parses_every_definition(self, functions):
        """One HookApiFunction per HOOK_API_DEFINITION in the macro file."""
        from hookz.config import load_config
        from hookz.xahaud_files import XahaudFile, resolve
        from pathlib import Path

        path = resolve(XahaudFile.HOOK_API_MACRO, load_config().xahaud_root)
        raw_count = Path(path).read_text().count("HOOK_API_DEFINITION(")
        assert raw_count > 0
        assert len(functions) == raw_count

    def test_guard_function_signature(self, functions):
        """int32_t _g(uint32_t, uint32_t) — the one every hook must import."""
        g = next(f for f in functions if f.name == "_g")
        assert g.return_type == "int32_t"
        assert g.param_types == ("uint32_t", "uint32_t")
        assert g.signature == (0x7F, 0x7F, 0x7F)
        assert g.amendment == ""

    def test_mixed_param_types(self, functions):
        """accept takes (uint32_t, uint32_t, int64_t) — i32, i32, i64."""
        accept = next(f for f in functions if f.name == "accept")
        assert accept.signature == (0x7E, 0x7F, 0x7F, 0x7E)

    def test_zero_parameter_api(self, functions):
        """`()` is not a legal C expression — the parser must not invent a param."""
        burden = next(f for f in functions if f.name == "etxn_burden")
        assert burden.param_types == ()
        assert burden.signature == (0x7E,)

    def test_amendment_gated_functions_exist(self, functions):
        gated = [f for f in functions if f.amendment]
        assert gated, "expected some amendment-gated APIs"
        assert all(f.amendment.startswith("feature") for f in gated)

    def test_ungated_functions_have_empty_amendment(self, functions):
        """`uint256{}` is the no-amendment sentinel and must normalise to ''."""
        assert any(f.amendment == "" for f in functions)
        assert not any(f.amendment == "0" for f in functions)

    def test_no_type_name_survives_substitution(self, functions):
        """Every parsed type must map to a known wasm code."""
        for f in functions:
            assert f.return_type in WASM_TYPE_CODE
            for p in f.param_types:
                assert p in WASM_TYPE_CODE

    def test_uint32_not_corrupted_by_int32_substitution(self, functions):
        """"uint32_t" contains "int32_t"; a careless replace would split it."""
        assert any("uint32_t" in f.param_types for f in functions)

    def test_unknown_type_is_an_error(self, tmp_path):
        macro = tmp_path / "bad.macro"
        macro.write_text(
            "HOOK_API_DEFINITION(\n  int32_t, thing, (float_t),\n  uint256{})\n"
        )
        with pytest.raises(ValueError, match="unrecognised hook API type"):
            parse_hook_api_macro(macro)

    def test_parses_a_definition_written_on_one_line(self, tmp_path):
        """Layout is the parser's business, not the caller's."""
        macro = tmp_path / "oneline.macro"
        macro.write_text("HOOK_API_DEFINITION(int64_t, thing, (uint32_t), uint256{})")
        fns = parse_hook_api_macro(macro)
        assert len(fns) == 1
        assert fns[0].name == "thing"
        assert fns[0].signature == (0x7E, 0x7F)

    def test_ignores_commented_out_definitions(self, tmp_path):
        """The macro file documents each API in a comment above it."""
        macro = tmp_path / "commented.macro"
        macro.write_text(
            "// int64_t ghost(uint32_t read_ptr);\n"
            "HOOK_API_DEFINITION(\n  int64_t, real, (uint32_t),\n  uint256{})\n"
        )
        names = [f.name for f in parse_hook_api_macro(macro)]
        assert names == ["real"]


class TestSignatureLayout:
    def test_signature_is_return_then_params(self, functions):
        for f in functions:
            assert f.signature[0] == WASM_TYPE_CODE[f.return_type]
            assert len(f.signature) == len(f.param_types) + 1

    def test_result_count_is_one_for_value_returns(self, functions):
        assert all(f.result_count == 1 for f in functions if f.return_type != "void_t")

    def test_coverage_import_matches_enum_h(self):
        """void __on_source_line(uint32_t, uint32_t) — no result, two i32."""
        assert COVERAGE_SIGNATURE == (VOID, 0x7F, 0x7F)
        sigs = get_import_signatures(coverage=True)
        assert sigs[COVERAGE_IMPORT] == COVERAGE_SIGNATURE

    def test_coverage_import_absent_by_default(self):
        assert COVERAGE_IMPORT not in get_import_signatures()


class TestAmendmentFiltering:
    def test_default_enables_everything(self, functions):
        assert get_whitelist() == {f.name for f in functions}

    def test_no_amendments_drops_gated_apis(self, functions):
        ungated = {f.name for f in functions if not f.amendment}
        assert get_whitelist(amendments=set()) == ungated
        assert len(ungated) < len(functions)

    def test_signatures_track_the_same_filter(self):
        assert set(get_import_signatures(amendments=set())) == get_whitelist(
            amendments=set()
        )

    def test_derive_amendments_matches_definitions(self, functions):
        assert derive_amendments(functions) == {f.amendment for f in functions if f.amendment}


class TestNormalisationSafety:
    """`_normalise` substitutes type names across the whole file.

    No current API or amendment embeds a type name, so nothing is corrupted
    today — but a future one would come back mangled, and a mangled name is a
    whitelist entry that no longer matches xahaud's. That must fail loudly
    rather than silently produce the wrong whitelist.
    """

    def test_name_embedding_a_type_name_is_rejected(self, tmp_path):
        macro = tmp_path / "evil.macro"
        macro.write_text(
            "HOOK_API_DEFINITION(int64_t, float_int32_t_hack, (uint32_t), uint256{})"
        )
        with pytest.raises(ValueError, match="contains the type name"):
            parse_hook_api_macro(macro)

    def test_amendment_embedding_a_type_name_is_rejected(self, tmp_path):
        """Substitution is by substring, so "Uint32_t" carries "int32_t" inside it."""
        macro = tmp_path / "evil2.macro"
        macro.write_text(
            "HOOK_API_DEFINITION(int64_t, thing, (uint32_t), featureUint32_tThing)"
        )
        with pytest.raises(ValueError, match="contains the type name"):
            parse_hook_api_macro(macro)

    def test_ordinary_amendment_name_survives(self, tmp_path):
        macro = tmp_path / "ok.macro"
        macro.write_text(
            "HOOK_API_DEFINITION(int64_t, thing, (uint32_t), featureHooksUpdate9)"
        )
        assert parse_hook_api_macro(macro)[0].amendment == "featureHooksUpdate9"

    def test_real_macro_is_free_of_the_hazard(self, functions):
        """The guard above is latent, not papering over a live corruption."""
        for f in functions:
            for type_name in WASM_TYPE_CODE:
                assert type_name not in f.name
                assert type_name not in f.amendment

    def test_whitelist_matches_xahaud_entry_count(self):
        """xahaud's getImportWhitelist() has exactly these entries.

        Hardcoded, not derived from the same parse this module performs —
        comparing a parse against itself cannot detect a dropped entry. 76 is
        the count printed by a getImportWhitelist() dump built from xahaud's
        own Enum.h: 75 hook APIs plus __on_source_line.
        """
        assert len(get_import_signatures()) == 75
        assert len(get_import_signatures(coverage=True)) == 76

    def test_dropped_entries_are_detected(self, tmp_path, monkeypatch):
        """A macro construct tree-sitter cannot parse must not fail silently.

        The check lives in parse_hook_api_macro, not only in this test file,
        because a whitelist short an API makes hookz reject imports xahaud
        allows — a false red light that would read as a bug in the hook.

        No known construct defeats the parser (several were tried), so the
        loss is simulated by dropping a call from the traversal.
        """
        from hookz.wasm import whitelist as W

        macro = tmp_path / "two.macro"
        macro.write_text(
            "HOOK_API_DEFINITION(int64_t, kept, (uint32_t), uint256{})\n"
            "HOOK_API_DEFINITION(int64_t, lost, (uint32_t), uint256{})\n"
        )
        assert len(parse_hook_api_macro(macro)) == 2

        # _iter_macro_calls recurses through the module global, so patching it
        # also cuts the recursion — the point is only that fewer calls come
        # back than the file contains, and that this is caught rather than
        # silently yielding a short whitelist.
        monkeypatch.setattr(W, "_iter_macro_calls", lambda node: iter(()))
        with pytest.raises(ValueError, match=r"parsed 0 .*file contains 2"):
            parse_hook_api_macro(macro)
