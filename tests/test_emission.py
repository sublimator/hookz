"""Tests for hookz.emission — the rules xahaud applies before accepting an emit.

`emit()` used to append the bytes and return 32 whatever they were, so a hook
that could not emit on chain passed here. These pin each rule against the
citation it comes from.
"""

import pytest

from hookz.emission import RULES, TYPE_VALIDATORS, check_emission
from hookz.wasm import xahaud_ref as ref


class TestRuleProvenance:
    def test_every_rule_cites_a_line_that_exists(self):
        assert ref.check_citations(
            __import__("pathlib").Path(
                __import__("hookz.emission", fromlist=["x"]).__file__).parent) == []

    @pytest.mark.parametrize("rule", RULES)
    def test_each_rule_carries_a_citation(self, rule):
        assert RULES[rule].startswith("xahaud:")

    def test_the_quorum_rule_cites_the_quorum_check(self):
        """The claim SignerListSet validation rests on."""
        c = ref.parse_citations(
            "xahaud:src/xrpld/app/tx/detail/SetSignerList.cpp:325")[0]
        assert "allSignersWeight < quorum" in c.snippet()


class TestUnreadable:
    """What hookz cannot decode, it does not judge.

    Two xahaud genesis hooks deliberately write 0x99 padding this parser
    cannot read, and the network accepts their emits. Reporting the fields
    after that point as "missing" blamed the hook for a limit of this tool —
    which is the whole error this module was written to stop making.
    """

    def test_an_unreadable_blob_is_recorded_not_rejected(self):
        check = check_emission(b"\x00\x01\x02not a transaction")
        assert check.undecodable
        assert check.rejections == []

    def test_it_says_how_far_it_got(self):
        check = check_emission(b"\xff" * 8)
        assert "bytes" in check.undecodable

    def test_a_readable_blob_is_judged(self):
        """The control — a decodable transaction still gets the rules."""
        from hookz.xrpl.txn_parser import parse_object
        blob = b"\x12\x00\x5f\x22\x80\x00\x00\x00\x24\x00\x00\x00\x00"
        assert parse_object(blob, strict=False).complete
        check = check_emission(blob)
        assert not check.undecodable
        assert check.rejections, "a transaction missing every required field"


class TestSignerListSetPreflight:
    """The sliver of preflight hookz reproduces, and why."""

    def test_it_is_registered(self):
        assert "SignerListSet" in TYPE_VALIDATORS

    @staticmethod
    def _fields(quorum, accounts, weights=None):
        weights = weights or [1] * len(accounts)
        return {
            "TransactionType": "SignerListSet",
            "SignerQuorum": quorum,
            "SignerEntries": [
                {"SignerEntry": {"Account": a, "SignerWeight": w}}
                for a, w in zip(accounts, weights)],
        }

    def _check(self, fields, account=None):
        from hookz.emission import EmissionCheck
        check = EmissionCheck()
        TYPE_VALIDATORS["SignerListSet"](fields, account, check)
        return check

    def test_a_reachable_quorum_passes(self):
        assert self._check(self._fields(2, ["rA", "rB", "rC"])).ok

    def test_a_quorum_above_the_summed_weights_is_refused(self):
        check = self._check(self._fields(5, ["rA", "rB", "rC"]))
        assert not check.ok and "temBAD_QUORUM" in str(check)

    def test_a_zero_quorum_is_refused(self):
        check = self._check(self._fields(0, ["rA", "rB"]))
        assert not check.ok and "temBAD_QUORUM" in str(check)

    def test_duplicate_signers_are_refused(self):
        check = self._check(self._fields(1, ["rA", "rA"]))
        assert not check.ok and "temBAD_SIGNER" in str(check)

    def test_a_zero_weight_signer_is_refused(self):
        check = self._check(self._fields(1, ["rA", "rB"], weights=[1, 0]))
        assert not check.ok and "temBAD_WEIGHT" in str(check)

    def test_an_empty_list_is_refused(self):
        check = self._check(self._fields(1, []))
        assert not check.ok and "temMALFORMED" in str(check)

    def test_a_destroy_is_not_judged_as_a_set(self):
        """No SignerEntries means a destroy, which these rules do not govern."""
        assert self._check({"TransactionType": "SignerListSet",
                            "SignerQuorum": 0}).ok


class TestCallbackAgreement:
    """sfEmitCallback is present exactly when the hook exports cbak."""

    BASE = {"Account": None, "Sequence": 0}

    def test_unknown_callback_state_is_not_an_accusation(self):
        """`has_callback=None` means the caller cannot tell — do not guess.

        Guessing here rejected every valid emit from every hook with a cbak.
        """
        blob = b"\x12\x00\x5f\x22\x80\x00\x00\x00\x24\x00\x00\x00\x00"
        check = check_emission(blob, has_callback=None)
        assert not any("EmitCallback" in r.detail for r in check.rejections)
