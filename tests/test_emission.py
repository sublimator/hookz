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


class TestIllegalVersusUnreadable:
    """Two different statements, and conflating them cost a round each way.

    Treating every incomplete parse as a refusal blamed genuine hooks for this
    parser's limits. Treating every one as "cannot judge" made a single NOP a
    universal bypass. The split is whether the failure is a rule xahaud itself
    enforces.
    """

    VALID = None   # built per-test; see _valid_tx below

    def test_more_than_sixty_four_nops_is_refused(self):
        """xahaud:src/libxrpl/protocol/STObject.cpp:223 throws, so this is the
        network's rule and not a shrug."""
        check = check_emission(_encode(_valid_tx()) + b"\x99" * 64,
                               hook_account=HOOK_ACCOUNT, ledger_seq=LEDGER)
        assert not check.ok
        assert not check.undecodable
        assert "parse" in _rules(check)

    def test_sixty_three_nops_is_still_judged_normally(self):
        check = check_emission(_encode(_valid_tx()) + b"\x99" * 63,
                               hook_account=HOOK_ACCOUNT, ledger_seq=LEDGER)
        assert check.ok and not check.undecodable

    @pytest.mark.parametrize("blob", [b"\xff" * 10, b"\x01\x02\x03not a txn"])
    def test_a_blob_with_no_readable_field_is_refused(self, blob):
        """Not a transaction by anyone's reading."""
        check = check_emission(blob)
        assert not check.ok and not check.undecodable

    # A known field header whose value runs off the end of the blob. The stop
    # is this parser meeting a limit, not a rule — xahaud is given the same
    # bytes by a different route and there is nothing here it enforces.
    TRUNCATED = bytes.fromhex("12005f") + bytes.fromhex("2400")

    # TransactionType, then Sequence = 99, then an Amount header with no value
    TRUNCATED_AFTER_A_BAD_SEQUENCE = bytes.fromhex("12005f24000000636100")

    def test_a_partly_readable_blob_still_declines(self):
        """Some fields recovered — this parser may simply be weaker here."""
        check = check_emission(self.TRUNCATED)
        assert check.undecodable and check.rejections == []

    def test_a_recovered_field_is_still_judged(self):
        """Declining to read the rest is not declining to look at what was read.

        A Sequence of 99 breaks rule 1 whatever follows it in the blob. If the
        undecodable branch skipped the rules outright, appending one byte that
        this parser cannot read would excuse any violation before it.
        """
        check = check_emission(self.TRUNCATED_AFTER_A_BAD_SEQUENCE)
        assert check.undecodable, "the tail really is unreadable"
        assert "1-sequence" in _rules(check)

    def test_an_absent_field_is_not_held_against_a_blob_it_never_reached(self):
        """The other half of the same rule: silence past the stop is not evidence."""
        check = check_emission(self.TRUNCATED)
        assert not any(r.detail.endswith("is missing") for r in check.rejections)

    @pytest.mark.parametrize("tail, why", [
        (b"\xfe", "a header naming no field xahaud knows"),
        (b"\xf1", "an end-of-array marker inside an object"),
        (b"\xe1", "an object terminator in a transaction"),
    ])
    def test_a_trailing_byte_xahaud_throws_on_is_refused(self, tail, why):
        """`STObject::set` throws on each of these, so none is a shrug.

        xahaud:src/libxrpl/protocol/STObject.cpp:243 and :253,
        xahaud:src/libxrpl/protocol/STTx.cpp:76. Left undecodable, any one of
        them would turn a rule-breaking emit into an accepted one.
        """
        check = check_emission(_encode(_valid_tx()) + tail,
                               hook_account=HOOK_ACCOUNT, ledger_seq=LEDGER)
        assert not check.ok, why
        assert "parse" in _rules(check)
        assert not check.undecodable

    def test_a_duplicate_field_is_refused(self):
        """xahaud:src/libxrpl/protocol/STObject.cpp:276 — the codec beneath this
        parser collapses repeats into a dict, where the last one silently wins."""
        check = check_emission(_encode(_valid_tx()) + bytes.fromhex("2400000000"),
                               hook_account=HOOK_ACCOUNT, ledger_seq=LEDGER)
        assert not check.ok
        assert "parse" in _rules(check)

    def test_a_violation_survives_a_trailing_garbage_byte(self):
        """The bypass this split exists to close, end to end."""
        tx = _valid_tx()
        tx["Sequence"] = 99
        assert "1-sequence" in _rules(_check(tx)), "control: refused on its own"

        check = check_emission(_encode(tx) + b"\xfe",
                               hook_account=HOOK_ACCOUNT, ledger_seq=LEDGER)
        assert not check.ok, "one unreadable byte must not launder a violation"


class TestUnreadable:
    """What hookz cannot decode, it does not judge.

    Two xahaud genesis hooks deliberately write 0x99 padding this parser
    cannot read, and the network accepts their emits. Reporting the fields
    after that point as "missing" blamed the hook for a limit of this tool —
    which is the whole error this module was written to stop making.
    """

    # a Sequence header with two of its four value bytes
    HALF = bytes.fromhex("12005f") + bytes.fromhex("2400")

    def test_a_partly_read_blob_is_recorded_not_rejected(self):
        check = check_emission(self.HALF)
        assert check.undecodable
        assert check.rejections == []

    def test_it_says_how_far_it_got(self):
        assert "bytes" in check_emission(self.HALF).undecodable

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


# ---------------------------------------------------------------------------
# One killing test per rule
# ---------------------------------------------------------------------------

def _encode(tx: dict) -> bytes:
    from hookz.xrpl.txn_parser import patch_xahau_definitions
    patch_xahau_definitions()
    from xrpl.core.binarycodec import encode
    return bytes.fromhex(encode(tx))


HOOK_ACCOUNT = b"\xa0" * 20
LEDGER = 100


def _valid_tx() -> dict:
    """A transaction xahaud would accept from a hook at ledger 100."""
    from hookz.account import to_raddr
    return {
        "TransactionType": "Payment",
        "Account": to_raddr(HOOK_ACCOUNT),
        "Destination": to_raddr(b"\x01" * 20),
        "Amount": "1000",
        "Sequence": 0,
        "Fee": "10",
        "SigningPubKey": "",
        "FirstLedgerSequence": LEDGER + 1,
        "LastLedgerSequence": LEDGER + 4,
        "EmitDetails": {
            "EmitGeneration": 1,
            "EmitBurden": 1,
            "EmitParentTxnID": "AB" * 32,
            "EmitNonce": "CD" * 32,
            "EmitHookHash": "00" * 32,
        },
    }


def _check(tx: dict, **kw):
    kw.setdefault("hook_account", HOOK_ACCOUNT)
    kw.setdefault("ledger_seq", LEDGER)
    return check_emission(_encode(tx), **kw)


class TestEachRuleFires:
    """Break one thing at a time; the matching rule must refuse it.

    Written after a review found eleven of thirteen mutants surviving: the
    sequence check, the ledger window, the fee, TxnSignature, EmitDetails,
    SigningPubKey, 2a/2b/2c, the callback agreement, generation and account
    could all be *deleted* with the suite still green. A validator nothing
    tests is a validator that quietly stops validating.
    """

    def test_the_baseline_is_accepted(self):
        """If this ever fails, every test below is testing nothing."""
        check = _check(_valid_tx())
        assert check.ok, str(check)
        assert not check.undecodable

    # -- rule 0 ------------------------------------------------------------

    def test_a_missing_account_is_refused(self):
        tx = _valid_tx()
        del tx["Account"]
        assert "0-account" in _rules(_check(tx))

    def test_another_accounts_transaction_is_refused(self):
        from hookz.account import to_raddr
        tx = _valid_tx()
        tx["Account"] = to_raddr(b"\x0b" * 20)
        assert "0-account" in _rules(_check(tx))

    # -- rule 1 ------------------------------------------------------------

    def test_a_nonzero_sequence_is_refused(self):
        tx = _valid_tx()
        tx["Sequence"] = 99
        assert "1-sequence" in _rules(_check(tx))

    # -- rule 2 ------------------------------------------------------------

    def test_a_nonzero_signing_pubkey_is_refused(self):
        tx = _valid_tx()
        tx["SigningPubKey"] = "02" + "00" * 32
        assert "2-signingpubkey" in _rules(_check(tx))

    def test_a_wrong_sized_signing_pubkey_is_refused(self):
        """Size must be 0 or 33 — a separate check from zeroness upstream."""
        tx = _valid_tx()
        tx["SigningPubKey"] = "00" * 5
        assert "2-signingpubkey" in _rules(_check(tx))

    # -- rules 2a/2b/2c ----------------------------------------------------

    def test_a_ticket_sequence_is_refused(self):
        tx = _valid_tx()
        tx["TicketSequence"] = 5
        assert "2b-ticket" in _rules(_check(tx))

    def test_an_account_txn_id_is_refused(self):
        tx = _valid_tx()
        tx["AccountTxnID"] = "EF" * 32
        assert "2c-accounttxnid" in _rules(_check(tx))

    # -- rule 3 ------------------------------------------------------------

    def test_missing_emit_details_is_refused(self):
        tx = _valid_tx()
        del tx["EmitDetails"]
        assert "3-emitdetails" in _rules(_check(tx))

    @pytest.mark.parametrize("missing", [
        "EmitGeneration", "EmitBurden", "EmitParentTxnID",
        "EmitNonce", "EmitHookHash"])
    def test_emit_details_must_be_valid_not_merely_present(self, missing):
        """Upstream requires all five; presence of the object is not enough."""
        tx = _valid_tx()
        del tx["EmitDetails"][missing]
        check = _check(tx)
        assert "3-emitdetails" in _rules(check)
        assert missing in str(check)

    def test_a_callback_for_another_account_is_refused(self):
        from hookz.account import to_raddr
        tx = _valid_tx()
        tx["EmitDetails"]["EmitCallback"] = to_raddr(b"\x0c" * 20)
        assert "3-emitdetails" in _rules(_check(tx, has_callback=True))

    def test_a_callback_is_refused_when_the_hook_has_no_cbak(self):
        from hookz.account import to_raddr
        tx = _valid_tx()
        tx["EmitDetails"]["EmitCallback"] = to_raddr(HOOK_ACCOUNT)
        assert "3-emitdetails" in _rules(_check(tx, has_callback=False))

    def test_a_missing_callback_is_refused_when_the_hook_has_cbak(self):
        assert "3-emitdetails" in _rules(_check(_valid_tx(), has_callback=True))

    # -- rule 8 ------------------------------------------------------------

    @pytest.mark.parametrize("generation", [10, 11, 99])
    def test_generation_ten_or_above_is_refused(self, generation):
        """`>= 10`, not `> 10` — the port accepted exactly 10."""
        tx = _valid_tx()
        tx["EmitDetails"]["EmitGeneration"] = generation
        assert "8-generation" in _rules(_check(tx))

    def test_generation_nine_is_accepted(self):
        tx = _valid_tx()
        tx["EmitDetails"]["EmitGeneration"] = 9
        assert _check(tx).ok

    # -- rule 4 ------------------------------------------------------------

    def test_a_signature_is_refused(self):
        tx = _valid_tx()
        tx["TxnSignature"] = "AB" * 32
        assert "4-txnsignature" in _rules(_check(tx))

    # -- rules 5 and 6 -----------------------------------------------------

    def test_a_missing_last_ledger_sequence_is_refused(self):
        tx = _valid_tx()
        del tx["LastLedgerSequence"]
        assert "5-lastledgerseq" in _rules(_check(tx))

    @pytest.mark.parametrize("lls", [LEDGER, LEDGER - 1, LEDGER + 6, LEDGER + 99])
    def test_a_last_ledger_sequence_outside_the_window_is_refused(self, lls):
        tx = _valid_tx()
        tx["LastLedgerSequence"] = lls
        tx["FirstLedgerSequence"] = min(tx["FirstLedgerSequence"], lls)
        assert "5-lastledgerseq" in _rules(_check(tx))

    @pytest.mark.parametrize("lls", [LEDGER + 1, LEDGER + 5])
    def test_the_window_edges_are_accepted(self, lls):
        tx = _valid_tx()
        tx["LastLedgerSequence"] = lls
        tx["FirstLedgerSequence"] = LEDGER + 1
        assert _check(tx).ok

    def test_a_missing_first_ledger_sequence_is_refused(self):
        tx = _valid_tx()
        del tx["FirstLedgerSequence"]
        assert "6-firstledgerseq" in _rules(_check(tx))

    def test_a_first_ledger_sequence_after_the_last_is_refused(self):
        tx = _valid_tx()
        tx["FirstLedgerSequence"] = tx["LastLedgerSequence"] + 1
        assert "6-firstledgerseq" in _rules(_check(tx))

    # -- rule 7 ------------------------------------------------------------

    def test_a_missing_fee_is_refused(self):
        tx = _valid_tx()
        del tx["Fee"]
        assert "7-fee" in _rules(_check(tx))

    def test_a_fee_below_the_floor_is_refused(self):
        tx = _valid_tx()
        tx["Fee"] = "5"
        assert "7-fee" in _rules(_check(tx, min_fee=10))

    # -- pseudo-transactions ------------------------------------------------

    def test_a_pseudo_transaction_is_refused(self):
        tx = _valid_tx()
        tx["TransactionType"] = "EnableAmendment"
        tx["Amendment"] = "AB" * 32
        tx["LedgerSequence"] = LEDGER
        for f in ("Destination", "Amount"):
            tx.pop(f, None)
        assert "pseudo" in _rules(_check(tx))

    # -- NOPs do not disable any of the above -------------------------------

    def test_a_nop_does_not_switch_validation_off(self):
        """One trailing 0x99 used to make every rule above stop running."""
        tx = _valid_tx()
        tx["Sequence"] = 99
        check = check_emission(_encode(tx) + b"\x99",
                               hook_account=HOOK_ACCOUNT, ledger_seq=LEDGER)
        assert not check.undecodable
        assert "1-sequence" in _rules(check)


def _rules(check) -> set[str]:
    return {r.rule for r in check.rejections}


class TestSignerCeiling:
    """8 signers, not 32, unless featureExpandedSignerList is active."""

    @staticmethod
    def _list(n: int):
        return {
            "TransactionType": "SignerListSet",
            "SignerQuorum": 1,
            "SignerEntries": [
                {"SignerEntry": {"Account": f"r{i:032d}", "SignerWeight": 1}}
                for i in range(n)],
        }

    def _check(self, n: int, expanded: bool):
        from hookz.emission import EmissionCheck, TYPE_VALIDATORS
        check = EmissionCheck()
        TYPE_VALIDATORS["SignerListSet"](
            self._list(n), None, check, expanded_signer_list=expanded)
        return check

    def test_nine_signers_are_refused_without_the_amendment(self):
        """hookz hardcoded 1..32 and accepted a list the network refuses."""
        check = self._check(9, expanded=False)
        assert not check.ok and "temMALFORMED" in str(check)

    def test_eight_signers_are_the_limit_without_it(self):
        assert self._check(8, expanded=False).ok

    def test_nine_signers_are_allowed_with_the_amendment(self):
        assert self._check(9, expanded=True).ok

    def test_thirty_three_are_refused_even_with_it(self):
        assert not self._check(33, expanded=True).ok


class TestNopCap:
    """xahaud throws past 64 NOPs; so does the parser."""

    BASE = bytes.fromhex("12005f22800000002400000000")

    def test_sixty_three_nops_still_parse(self):
        from hookz.xrpl.txn_parser import parse_object
        assert parse_object(self.BASE + b"\x99" * 63, strict=False).complete

    def test_sixty_four_nops_are_too_many(self):
        """xahaud:src/libxrpl/protocol/STObject.cpp:223 throws at 64."""
        from hookz.xrpl.txn_parser import parse_object
        result = parse_object(self.BASE + b"\x99" * 64, strict=False)
        assert not result.complete
        assert "NOP" in str(result.error)


class TestKnownGapsAreStated:
    """A gap nobody wrote down is a gap nobody fixes."""

    def test_the_gaps_are_enumerated(self):
        from hookz.emission import KNOWN_GAPS
        assert len(KNOWN_GAPS) >= 5
        assert all(isinstance(g, str) and g for g in KNOWN_GAPS)

    def test_the_fee_floor_gap_is_real(self):
        """Documented because handlers/emit.py passes min_fee=None."""
        import inspect
        from hookz.handlers import emit as handler
        assert "min_fee=None" in inspect.getsource(handler.emit)


class TestEveryReasonIsReported:
    """`check_emission` promises every reason, not the first — untested until
    a review added an early `return` and no test noticed."""

    def test_two_broken_things_give_two_rules(self):
        tx = _valid_tx()
        tx["Sequence"] = 99
        del tx["Fee"]
        rules = _rules(_check(tx))
        assert {"1-sequence", "7-fee"} <= rules

    def test_a_wrong_account_does_not_stop_later_rules(self):
        from hookz.account import to_raddr

        tx = _valid_tx()
        tx["Account"] = to_raddr(b"\x0b" * 20)
        tx["Sequence"] = 42
        rules = _rules(_check(tx))
        assert {"0-account", "1-sequence"} <= rules


class TestMalformationInsideANestedObject:
    """The rules run at every level, not only the transaction's own.

    `STObject::set` recurses — `v_.emplace_back(sit, fn, depth + 1)`
    (xahaud:src/libxrpl/protocol/STObject.cpp:264) — so a duplicate or an
    unknown field inside EmitDetails throws exactly as it would at the top.
    xrpl-py instead consumes a nested object whole and folds repeats into a
    dict where the last wins, so the outer parse comes back clean and the
    fourteen rules are applied to a transaction the network would refuse.

    Reported as the third instance of the same hole, one layer deeper than
    rounds 2 and 3 found it.
    """

    @staticmethod
    def _emit_details_span(blob: bytes) -> tuple[int, int]:
        """(first byte of contents, offset of the closing terminator)."""
        return blob.find(bytes([0xED])) + 1, blob.rfind(bytes([0xE1]))

    def test_a_duplicate_field_inside_emit_details_is_refused(self):
        blob = _encode(_valid_tx())
        start, end = self._emit_details_span(blob)
        duplicated = blob[:end] + blob[start:start + 6] + blob[end:]

        check = check_emission(duplicated, hook_account=HOOK_ACCOUNT,
                               ledger_seq=LEDGER)

        assert not check.ok, "xahaud throws Duplicate field detected"
        assert "parse" in _rules(check)

    def test_the_unmodified_transaction_still_passes(self):
        """The control — the recursion must not refuse a well-formed nest."""
        check = _check(_valid_tx())

        assert check.ok, str(check)
        assert not check.undecodable

    def test_a_nested_duplicate_is_reported_as_illegal_not_undecodable(self):
        """It is upstream's rule, so it is a refusal rather than a shrug."""
        from hookz.xrpl.txn_parser import parse_object

        blob = _encode(_valid_tx())
        start, end = self._emit_details_span(blob)
        duplicated = blob[:end] + blob[start:start + 6] + blob[end:]

        parsed = parse_object(duplicated, strict=False)

        assert parsed.illegal
        assert "duplicate" in str(parsed.error).lower()

    def test_the_depth_is_bounded(self):
        """A malformed blob must not drive the recursion without limit."""
        from hookz.xrpl.txn_parser import _nested_problem

        assert _nested_problem(b"", depth=65) is not None


class TestRepetitionInsideAnArrayIsLegal:
    """An array holds many elements of one named type, and that is not a
    duplicate field.

    `STObject::set` runs the duplicate check per object — `getSortedFields`
    over one object's own fields (xahaud:src/libxrpl/protocol/STObject.cpp:270)
    — and each array element is its own object. Applying the object rule to
    the array body rejects every signer list with more than one signer, which
    is the false-refusal direction and the expensive one.
    """

    @staticmethod
    def _signer_list(n: int) -> dict:
        from hookz.account import to_raddr

        tx = _valid_tx()
        tx["TransactionType"] = "SignerListSet"
        tx.pop("Amount", None)
        tx.pop("Destination", None)
        tx["SignerQuorum"] = 1
        tx["SignerEntries"] = [
            {"SignerEntry": {"Account": to_raddr(bytes([i + 1]) * 20),
                             "SignerWeight": 1}}
            for i in range(n)
        ]
        return tx

    @pytest.mark.parametrize("n", [1, 2, 5])
    def test_repeated_elements_are_not_a_duplicate_field(self, n):
        from hookz.xrpl.txn_parser import parse_object

        parsed = parse_object(_encode(self._signer_list(n)), strict=False)

        assert parsed.complete, str(parsed.error)
        assert not parsed.illegal
        assert len(parsed.fields["SignerEntries"]) == n

    def test_a_duplicate_inside_one_element_is_still_caught(self):
        """The rule still applies within an element, which is an object."""
        from hookz.xrpl.txn_parser import _nested_problem

        # SignerWeight (0x13 0x01) twice inside one element's contents
        element = bytes.fromhex("130001") + bytes.fromhex("130001")
        assert _nested_problem(element, depth=1) is not None
