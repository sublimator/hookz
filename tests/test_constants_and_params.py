"""Generated constants, param maps, and package exports.

The values asserted here are ones downstream test suites previously carried
as local constants with `xahaud:` citations — the generated modules must
agree with those citations, not merely with themselves.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import hookz
from hookz import CALLBACK_APPLIED, CALLBACK_NOT_APPLIED, emitted_txn_id
from hookz import flags, ter
from hookz.runtime import HookRuntime, ParamMap

SRC = Path(__file__).resolve().parent.parent / "src" / "hookz"

#: A generated constant line: `tecDST_TAG_NEEDED = 143  # xahaud:...`
_ASSIGNMENT = re.compile(r"^[a-zA-Z]\w* = (?:-?\d|0x)")


def _constant_assignments(path: Path) -> list[str]:
    return [
        line for line in path.read_text().splitlines()
        if _ASSIGNMENT.match(line)
    ]


class TestTerConstants:
    def test_the_cited_values(self):
        # xahaud:include/xrpl/protocol/TER.h:253,280,284,304,308
        assert ter.tesSUCCESS == 0
        assert ter.tecCLAIM == 100
        assert ter.tecUNFUNDED_PAYMENT == 104
        assert ter.tecNO_PERMISSION == 139
        assert ter.tecDST_TAG_NEEDED == 143

    def test_both_directions_resolve(self):
        assert ter.name(143) == "tecDST_TAG_NEEDED"
        assert ter.code("tecDST_TAG_NEEDED") == 143
        assert ter.name(ter.code("tesSUCCESS")) == "tesSUCCESS"

    def test_negative_ranges_are_present(self):
        assert ter.telLOCAL_ERROR == -399
        assert ter.temMALFORMED == -299

    def test_every_constant_carries_a_citation(self):
        """The xahaud: provenance convention is part of the module contract."""
        assignments = _constant_assignments(SRC / "ter.py")
        assert len(assignments) > 150
        for line in assignments:
            assert "# xahaud:include/xrpl/protocol/TER.h:" in line, line


class TestFlagConstants:
    def test_the_cited_values(self):
        assert flags.tfFullyCanonicalSig == 0x80000000
        assert flags.tfPartialPayment == 0x00020000
        assert flags.tfSetFreeze == 0x00100000
        assert flags.tfClearFreeze == 0x00200000
        assert flags.lsfRequireDestTag == 0x00020000
        assert flags.lsfDisallowIncomingRemit == 0x80000000

    def test_every_constant_carries_a_citation(self):
        assignments = _constant_assignments(SRC / "flags.py")
        assert len(assignments) > 100
        for line in assignments:
            assert "# xahaud:include/xrpl/protocol/" in line, line


class TestParamMaps:
    def test_str_and_bytes_keys_are_one_parameter(self):
        rt = HookRuntime()
        rt.params["CMD"] = b"SWAP"
        assert rt.params[b"CMD"] == b"SWAP"
        assert "CMD" in rt.params and b"CMD" in rt.params
        rt.tx_params[b"AMT"] = b"\x01"
        assert rt.tx_params.get("AMT") == b"\x01"

    def test_assigning_a_plain_dict_normalizes_it(self):
        rt = HookRuntime()
        rt.params = {"CUR": b"USD", b"ISSUER": b"\x15" * 20}
        assert rt.params[b"CUR"] == b"USD"
        assert rt.params["ISSUER"] == b"\x15" * 20
        assert isinstance(rt.params, ParamMap)

    def test_update_pop_setdefault_and_del(self):
        rt = HookRuntime()
        rt.tx_params.update({"A": b"1"}, B=b"2")
        assert rt.tx_params[b"A"] == b"1" and rt.tx_params[b"B"] == b"2"
        assert rt.tx_params.pop("A") == b"1"
        assert rt.tx_params.pop("A", None) is None
        rt.tx_params.setdefault("C", b"3")
        assert rt.tx_params["C"] == b"3"
        del rt.tx_params["C"]
        assert b"C" not in rt.tx_params

    def test_a_str_key_overrides_its_bytes_twin(self):
        """Mixed-key dicts collapse in insertion order — later spelling wins."""
        rt = HookRuntime()
        rt.params = {b"CUR": b"OLD", "CUR": b"NEW"}
        assert rt.params[b"CUR"] == b"NEW"
        assert len(rt.params) == 1

    def test_set_param_int_keys_still_work(self):
        rt = HookRuntime()
        rt.set_param(0, b"value")
        assert rt.params[b"\x00"] == b"value"


class TestParamMapUnionAndCopy:
    """dict's own union/copy skip __setitem__ — these must not."""

    def test_in_place_union_normalizes(self):
        m = ParamMap()
        m |= {"CMD": b"SWAP"}
        assert m[b"CMD"] == b"SWAP"
        assert "CMD" in m and len(m) == 1

    def test_union_returns_a_normalized_parammap(self):
        merged = ParamMap({"A": b"1"}) | {"B": b"2"}
        assert isinstance(merged, ParamMap)
        assert merged[b"A"] == b"1" and merged[b"B"] == b"2"

    def test_reflected_union_normalizes_the_plain_side(self):
        merged = {"A": b"1"} | ParamMap({"B": b"2"})
        assert isinstance(merged, ParamMap)
        assert merged[b"A"] == b"1" and merged[b"B"] == b"2"

    def test_copy_stays_a_parammap(self):
        copied = ParamMap({"A": b"1"}).copy()
        assert isinstance(copied, ParamMap)
        copied["B"] = b"2"
        assert copied[b"B"] == b"2"


class TestConstexprFlags:
    """TxFlags.h defines the AMM flags and every mask as constexpr, not
    enumerators — the table has to carry them too."""

    def test_the_amm_flags_are_present(self):
        assert flags.tfLPToken == 0x00010000
        assert flags.tfWithdrawAll == 0x00020000

    def test_a_mask_expression_evaluates_with_uint32_wrap(self):
        # ~(tfUniversal | tfPartialPayment | tfLimitQuality |
        #   tfNoRippleDirect) as the chain stores it, not a negative int.
        assert flags.tfUniversal == 0x80000000
        assert flags.tfPaymentMask == 0x7FF8FFFF
        assert flags.tfPaymentMask > 0


class TestGeneratorBehavior:
    """The parser shapes the generated modules depend on, run directly."""

    HEADER = """
enum Plain {
    first = -3,
    second,
    third = 0x10,
    fourth,
};

enum Wide : uint32_t {
    bit = 0x80000000,
    mask = ~bit,
};

constexpr std::uint32_t const combined = bit | third;
constexpr std::uint32_t inverted = ~(bit | third);
"""

    def _repo(self, tmp_path):
        from hookz.xrpl.xahaud import XahaudRepo

        (tmp_path / "synthetic.h").write_text(self.HEADER)
        return XahaudRepo(tmp_path)

    def test_implicit_increment_hex_and_negative_starts(self, tmp_path):
        parsed = {
            c.name: c
            for c in self._repo(tmp_path).parse_enum_constants("synthetic.h")
        }
        assert parsed["first"].value == -3
        assert parsed["second"].value == -2, "implicit increment broke"
        assert parsed["third"].value == 0x10
        assert parsed["fourth"].value == 0x11
        assert parsed["first"].line == 3, "citation lines drifted"

    def test_unsigned_enums_wrap_mask_expressions(self, tmp_path):
        parsed = {
            c.name: c.value
            for c in self._repo(tmp_path).parse_enum_constants("synthetic.h")
        }
        assert parsed["bit"] == 0x80000000
        assert parsed["mask"] == 0x7FFFFFFF, "~ must wrap to uint32"

    def test_constexpr_values_are_opt_in_and_share_the_environment(
        self, tmp_path
    ):
        repo = self._repo(tmp_path)
        without = {c.name for c in repo.parse_enum_constants("synthetic.h")}
        assert "combined" not in without

        parsed = {
            c.name: c
            for c in repo.parse_enum_constants(
                "synthetic.h", constexpr_too=True
            )
        }
        assert parsed["combined"].value == 0x80000010
        assert parsed["inverted"].value == 0x7FFFFFEF
        assert parsed["combined"].enum == "constexpr"

    def test_a_shared_environment_crosses_files(self, tmp_path):
        repo = self._repo(tmp_path)
        (tmp_path / "other.h").write_text(
            "enum Uses : uint32_t { borrowed = bit | 1 };\n"
        )
        env: dict[str, int] = {}
        repo.parse_enum_constants("synthetic.h", env)
        parsed = {
            c.name: c.value for c in repo.parse_enum_constants("other.h", env)
        }
        assert parsed["borrowed"] == 0x80000001

    def test_generation_is_idempotent_against_the_vendored_tree(self):
        """The checked-in modules are what the generator produces, byte for
        byte apart from the Source line (the vendored tree is not a git
        checkout, so its Source identity legitimately differs)."""
        from hookz.xahaud_files import _vendored_root
        from hookz.xrpl.xahaud import XahaudRepo

        repo = XahaudRepo(_vendored_root())

        def _without_source(text: str) -> str:
            return "\n".join(
                line for line in text.splitlines()
                if not line.startswith("Source: ")
            )

        assert _without_source(repo.generate_ter_py()) == _without_source(
            (SRC / "ter.py").read_text()
        )
        assert _without_source(repo.generate_flags_py()) == _without_source(
            (SRC / "flags.py").read_text()
        )


class TestCitationClosure:
    def test_every_citation_names_a_registered_file(self):
        """A vendored file can resolve citations while silently bypassing the
        pin comparison — registration in PORTED_FILES/CITED_FILES is what
        subjects it to `verify_vendored`, so citation and registry must agree.
        """
        from hookz.wasm.xahaud_ref import CITED_FILES, PORTED_FILES

        registered = set(PORTED_FILES) | set(CITED_FILES)
        pattern = re.compile(r"xahaud:([A-Za-z0-9_./-]+\.(?:h|cpp|macro))")
        unregistered: set[str] = set()
        for path in SRC.rglob("*.py"):
            if "xahaud_lite" in path.parts:
                continue
            for cited in pattern.findall(path.read_text()):
                if cited not in registered:
                    unregistered.add(cited)
        assert not unregistered, sorted(unregistered)


class TestExports:
    def test_callback_constants_are_reachable_from_the_root(self):
        assert CALLBACK_APPLIED == 0
        assert CALLBACK_NOT_APPLIED == 1
        assert hookz.CALLBACK_APPLIED is CALLBACK_APPLIED

    def test_emitted_txn_id_is_the_txn_hash_prefix_form(self):
        blob = b"\x12\x00\x5f"
        expected = hashlib.sha512(b"TXN\x00" + blob).digest()[:32]
        assert emitted_txn_id(blob) == expected
        assert len(emitted_txn_id(b"")) == 32
