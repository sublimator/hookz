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
