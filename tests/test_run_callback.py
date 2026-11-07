"""`run_callback` — the second execution the ledger owes an emitting hook.

The cbak probe below reads every surface `run_callback` derives — `otxn_id`,
the provisional metadata through `meta_slot`, the slotted originating
transaction, direct field reads — and records each answer into state under a
known key, so the assertions here are byte-level and need no private fields.
"""

from __future__ import annotations

import pytest

from hookz import hookapi
from hookz.emission import emitted_txn_id
from hookz.handlers.otxn import CALLBACK_APPLIED, CALLBACK_NOT_APPLIED
from hookz.runtime import HookRuntime, provisional_meta
from hookz.xrpl.txn_builder import serialize_fields

SOURCE = """
#include "hookapi.h"

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    etxn_reserve(1);
    uint8_t key[2] = {'T', 'X'};
    uint8_t tx[128];
    int64_t len = hook_param(SBUF(tx), SBUF(key));
    if (len <= 0)
        return rollback(SBUF("no tx param"), 1);
    uint8_t hsh[32];
    emit(SBUF(hsh), tx, (uint32_t)len);
    return accept(SBUF("emitted"), 0);
}

int64_t cbak(uint32_t ctx)
{
    _g(1, 1);
    uint8_t k[32] = {0};

    uint8_t id[32];
    if (otxn_id(SBUF(id), 0) == 32)
    {
        k[0] = 0x01;
        state_set(SBUF(id), SBUF(k));
    }

    int64_t ms = meta_slot(0);
    uint8_t ms_buf[8];
    INT64_TO_BUF(ms_buf, ms);
    k[0] = 0x02;
    state_set(SBUF(ms_buf), SBUF(k));
    if (ms > 0)
    {
        int64_t fs = slot_subfield(ms, sfTransactionResult, 0);
        if (fs > 0)
        {
            uint8_t res[1];
            if (slot(SBUF(res), fs) == 1)
            {
                k[0] = 0x03;
                state_set(SBUF(res), SBUF(k));
            }
        }
    }

    int64_t os = otxn_slot(0);
    if (os > 0)
    {
        uint8_t blob[256];
        int64_t blen = slot(SBUF(blob), os);
        if (blen > 0)
        {
            k[0] = 0x04;
            state_set(blob, (uint32_t)blen, SBUF(k));
        }
    }

    uint8_t dest[20];
    int64_t drc = otxn_field(SBUF(dest), sfDestination);
    uint8_t drc_buf[8];
    INT64_TO_BUF(drc_buf, drc);
    k[0] = 0x05;
    state_set(SBUF(drc_buf), SBUF(k));
    if (drc == 20)
    {
        k[0] = 0x0A;
        state_set(SBUF(dest), SBUF(k));
    }

    uint8_t acct[20];
    if (otxn_field(SBUF(acct), sfAccount) == 20)
    {
        k[0] = 0x0B;
        state_set(SBUF(acct), SBUF(k));
    }

    uint8_t flg[4];
    if (otxn_field(SBUF(flg), sfFlags) == 4)
    {
        k[0] = 0x0C;
        state_set(SBUF(flg), SBUF(k));
    }

    uint8_t amt[8];
    if (otxn_field(SBUF(amt), sfAmount) == 8)
    {
        k[0] = 0x0D;
        state_set(SBUF(amt), SBUF(k));
    }

    uint8_t tag[4];
    if (otxn_field(SBUF(tag), sfSourceTag) == 4)
    {
        k[0] = 0x06;
        state_set(SBUF(tag), SBUF(k));
    }

    int64_t ot = otxn_type();
    uint8_t ot_buf[8];
    INT64_TO_BUF(ot_buf, ot);
    k[0] = 0x07;
    state_set(SBUF(ot_buf), SBUF(k));

    uint8_t seq[4];
    if (otxn_field(SBUF(seq), sfLedgerSequence) == 4)
    {
        k[0] = 0x08;
        state_set(SBUF(seq), SBUF(k));
    }

    uint8_t th[32];
    if (otxn_field(SBUF(th), sfTransactionHash) == 32)
    {
        k[0] = 0x09;
        state_set(SBUF(th), SBUF(k));
    }

    uint8_t vl[16];
    int64_t vrc = otxn_field(SBUF(vl), sfBlob);
    if (vrc > 0)
    {
        k[0] = 0x0E;
        state_set(vl, (uint32_t)vrc, SBUF(k));
    }

    uint8_t arr[32];
    int64_t arc = otxn_field(SBUF(arr), sfMemos);
    if (arc > 0)
    {
        k[0] = 0x10;
        state_set(arr, (uint32_t)arc, SBUF(k));
    }

    uint8_t ed[32];
    int64_t erc = otxn_field(SBUF(ed), sfEmitDetails);
    if (erc > 0)
    {
        k[0] = 0x14;
        state_set(ed, (uint32_t)erc, SBUF(k));
    }

    int64_t os2 = otxn_slot(0);
    if (os2 > 0)
    {
        int64_t bs = slot_subfield(os2, sfBlob, 0);
        if (bs > 0)
        {
            uint8_t b2[16];
            int64_t l2 = slot(SBUF(b2), bs);
            if (l2 > 0)
            {
                k[0] = 0x0F;
                state_set(b2, (uint32_t)l2, SBUF(k));
            }
        }
        int64_t as = slot_subfield(os2, sfMemos, 0);
        if (as > 0)
        {
            uint8_t a2[32];
            int64_t l3 = slot(SBUF(a2), as);
            if (l3 > 0)
            {
                k[0] = 0x11;
                state_set(a2, (uint32_t)l3, SBUF(k));
            }
        }
        int64_t es = slot_subfield(os2, sfEmitDetails, 0);
        if (es > 0)
        {
            uint8_t e2[32];
            int64_t l4 = slot(SBUF(e2), es);
            if (l4 > 0)
            {
                k[0] = 0x12;
                state_set(e2, (uint32_t)l4, SBUF(k));
            }
            int64_t ts = slot_subfield(es, sfSourceTag, 0);
            if (ts > 0)
            {
                uint8_t t2[4];
                if (slot(SBUF(t2), ts) == 4)
                {
                    k[0] = 0x13;
                    state_set(SBUF(t2), SBUF(k));
                }
            }
        }
    }

    uint8_t pk[3] = {'C', 'M', 'D'};
    uint8_t pv[16];
    int64_t prc = otxn_param(SBUF(pv), SBUF(pk));
    uint8_t prc_buf[8];
    INT64_TO_BUF(prc_buf, prc);
    k[0] = 0x15;
    state_set(SBUF(prc_buf), SBUF(k));
    if (prc > 0)
    {
        k[0] = 0x16;
        state_set(pv, (uint32_t)prc, SBUF(k));
    }

    return accept(SBUF("probed"), 0);
}
"""

K_ID = bytes([0x01]) + b"\x00" * 31
K_META_RC = bytes([0x02]) + b"\x00" * 31
K_RESULT = bytes([0x03]) + b"\x00" * 31
K_OTXN = bytes([0x04]) + b"\x00" * 31
K_DEST_RC = bytes([0x05]) + b"\x00" * 31
K_TAG = bytes([0x06]) + b"\x00" * 31
K_TYPE = bytes([0x07]) + b"\x00" * 31
K_SEQ = bytes([0x08]) + b"\x00" * 31
K_HASH = bytes([0x09]) + b"\x00" * 31
K_DEST = bytes([0x0A]) + b"\x00" * 31
K_ACCT = bytes([0x0B]) + b"\x00" * 31
K_FLAGS = bytes([0x0C]) + b"\x00" * 31
K_AMOUNT = bytes([0x0D]) + b"\x00" * 31
K_VL = bytes([0x0E]) + b"\x00" * 31
K_VL_SLOT = bytes([0x0F]) + b"\x00" * 31
K_ARR = bytes([0x10]) + b"\x00" * 31
K_ARR_SLOT = bytes([0x11]) + b"\x00" * 31
K_OBJ = bytes([0x12]) + b"\x00" * 31
K_OBJ_TAG = bytes([0x13]) + b"\x00" * 31
K_OBJ_DIRECT = bytes([0x14]) + b"\x00" * 31
K_PARAM_RC = bytes([0x15]) + b"\x00" * 31
K_PARAM = bytes([0x16]) + b"\x00" * 31

DEST = bytes([0xDD]) + b"\x00" * 19
ACCT = bytes([0xAA]) + b"\x00" * 19
FLAGS = (5).to_bytes(4, "big")
#: 1000 drops in the native STAmount encoding (positive-XRP bit set).
AMOUNT = (1000 | (1 << 62)).to_bytes(8, "big")


def i64buf(value: int) -> bytes:
    """INT64_TO_BUF's encoding: big-endian two's-complement int64."""
    return (value & (2**64 - 1)).to_bytes(8, "big")


def payment_blob(*, source_tag: int | None = None,
                 tx_type: int = 0) -> bytes:
    """A serialized transaction the cbak can slot, echo, and field-read."""
    fields = {
        hookapi.sfTransactionType: tx_type.to_bytes(2, "big"),
        hookapi.sfFlags: FLAGS,
        hookapi.sfAmount: AMOUNT,
        hookapi.sfAccount: ACCT,
        hookapi.sfDestination: DEST,
    }
    if source_tag is not None:
        fields[hookapi.sfSourceTag] = source_tag.to_bytes(4, "big")
    return serialize_fields(fields)


#: One empty Memo object, as it sits inside a serialized sfMemos array:
#: the element's own field header and closing marker.
MEMO_ELEMENT = b"\xEA\xE1"
#: Contents of the sfEmitDetails object: a single inner SourceTag.
OBJ_CONTENTS = bytes([0x23]) + (42).to_bytes(4, "big")


def rich_blob() -> bytes:
    """payment_blob's shape plus one VL, one array, and one object field."""
    fields = {
        hookapi.sfTransactionType: (0).to_bytes(2, "big"),
        hookapi.sfBlob: b"abc",
        hookapi.sfMemos: MEMO_ELEMENT + b"\xF1",
        hookapi.sfEmitDetails: OBJ_CONTENTS + b"\xE1",
        hookapi.sfDestination: DEST,
    }
    return serialize_fields(fields)


@pytest.fixture(scope="module")
def wasm(tmp_path_factory):
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    config = load_config()
    if not (config.wasi_sdk / "bin" / "clang").exists():
        pytest.skip("wasi-sdk not found")
    source = tmp_path_factory.mktemp("cbak_probe") / "cbak_probe.c"
    source.write_text(SOURCE)
    return compile_hook(source, None, config)


class TestAppliedMode:
    def test_the_emission_is_the_originating_transaction(self, wasm):
        blob = payment_blob(source_tag=777)
        rt = HookRuntime()
        result = rt.run_callback(wasm, emitted_tx=blob)
        assert result.accepted

        assert rt.state_db[K_ID] == emitted_txn_id(blob)
        assert rt.state_db[K_OTXN] == blob
        assert rt.state_db[K_TAG] == (777).to_bytes(4, "big")
        assert rt.state_db[K_TYPE] == i64buf(0)
        # The failure-only fields are exactly not present.
        assert K_SEQ not in rt.state_db
        assert K_HASH not in rt.state_db

    def test_the_metadata_carries_the_result(self, wasm):
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        transaction_result="tecUNFUNDED_PAYMENT")
        from hookz import ter
        assert rt.state_db[K_RESULT] == bytes(
            [ter.tecUNFUNDED_PAYMENT & 0xFF])

    def test_str_and_int_results_serialize_identically(self):
        from hookz import ter
        assert provisional_meta("tesSUCCESS") == provisional_meta(
            ter.tesSUCCESS)
        assert provisional_meta("tecUNFUNDED_PAYMENT") == provisional_meta(
            ter.tecUNFUNDED_PAYMENT)

    def test_transaction_type_is_derived_from_the_blob(self, wasm):
        from xrpl.core.binarycodec.definitions import definitions
        remit = definitions.get_transaction_type_code("Remit")
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(tx_type=remit))
        assert rt.state_db[K_TYPE] == i64buf(remit)

    def test_direct_field_reads_derive_from_the_emission(self, wasm):
        """Upstream, `otxn_field` and `otxn_slot` describe the same
        `applyCtx.tx` — so every field the emission carries is directly
        readable, without the caller repeating it."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(source_tag=777))

        assert rt.state_db[K_DEST_RC] == i64buf(20)
        assert rt.state_db[K_DEST] == DEST
        assert rt.state_db[K_ACCT] == ACCT
        assert rt.state_db[K_FLAGS] == FLAGS
        assert rt.state_db[K_AMOUNT] == AMOUNT
        assert rt.state_db[K_TAG] == (777).to_bytes(4, "big")

    def test_the_emission_overrides_a_conflicting_caller_field(self, wasm):
        """A caller-set field that disagrees with the emission is a delivery
        the ledger cannot make: the blob is the authority for both the
        direct and the slotted view. The caller's value comes back with the
        restore — it configures later plain runs, not this delivery."""
        other = bytes([0xEE]) + b"\x00" * 19
        rt = HookRuntime()
        rt.otxn_fields[hookapi.sfDestination] = other
        rt.run_callback(wasm, emitted_tx=payment_blob())

        assert rt.state_db[K_DEST] == DEST
        assert rt.state_db[K_OTXN] == payment_blob()
        assert rt.otxn_fields[hookapi.sfDestination] == other

    def test_a_caller_field_absent_from_the_emission_still_serves(self, wasm):
        rt = HookRuntime()
        rt.otxn_fields[hookapi.sfSourceTag] = (999).to_bytes(4, "big")
        rt.run_callback(wasm, emitted_tx=payment_blob())

        assert rt.state_db[K_TAG] == (999).to_bytes(4, "big")
        assert rt.otxn_fields[hookapi.sfSourceTag] == (999).to_bytes(4, "big")

    def test_an_explicit_tx_hash_wins(self, wasm):
        custom = bytes(range(32))
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(), tx_hash=custom)
        assert rt.state_db[K_ID] == custom


class TestFieldProjections:
    """Every field answer is its `STBase::add` serialization — VL prefixes
    kept (except accounts), object/array values contents-only — and the
    direct and slotted views agree byte for byte
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1941)."""

    def test_vl_array_and_object_values_match_the_host(self, wasm):
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=rich_blob())

        # STBlob keeps its length prefix on both paths.
        assert rt.state_db[K_VL] == b"\x03abc"
        assert rt.state_db[K_VL_SLOT] == b"\x03abc"
        # An array's value is its elements only — no outer header, no F1.
        assert rt.state_db[K_ARR] == MEMO_ELEMENT
        assert rt.state_db[K_ARR_SLOT] == MEMO_ELEMENT
        # An object's value is its contents only — no outer header, no E1 —
        # and the slotted copy still navigates deeper.
        assert rt.state_db[K_OBJ_DIRECT] == OBJ_CONTENTS
        assert rt.state_db[K_OBJ] == OBJ_CONTENTS
        assert rt.state_db[K_OBJ_TAG] == (42).to_bytes(4, "big")

    def test_an_empty_array_projects_to_nothing(self):
        """`STArray::add` of an empty array serializes nothing — the F8
        header and F1 closer belong to the containing object."""
        from hookz.runtime import _emission_fields

        blob = serialize_fields({
            hookapi.sfTransactionType: (0).to_bytes(2, "big"),
            hookapi.sfAffectedNodes: b"\xF1",
        })
        assert _emission_fields(blob)[hookapi.sfAffectedNodes] == b""


class TestNotAppliedMode:
    """fix20261005 (on mainnet): a failure callback reads the original
    emission, not the ttEMIT_FAILURE pseudo-transaction
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1591)."""

    def test_the_hook_reads_the_original_not_the_pseudo(self, wasm):
        blob = payment_blob(source_tag=777)
        rt = HookRuntime()
        rt.ledger_seq_val = 100_001
        result = rt.run_callback(wasm, emitted_tx=blob,
                                 ctx=CALLBACK_NOT_APPLIED)
        assert result.accepted

        # The pseudo carries these two; the emission does not, and the
        # emission is what presence is checked on.
        assert K_SEQ not in rt.state_db
        assert K_HASH not in rt.state_db
        # otxn_id is still the pseudo's sfTransactionHash: the emission's.
        assert rt.state_db[K_ID] == emitted_txn_id(blob)
        assert rt.state_db[K_TYPE] == i64buf(0)
        assert rt.state_db[K_TAG] == (777).to_bytes(4, "big")

    def test_the_restore_path_can_find_its_record(self, wasm):
        """What a failure cbak needs to undo the emission is readable: a
        cbak that opens by reading sfDestination to find whose record to
        restore takes the restore."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_DEST_RC] == i64buf(20)
        assert rt.state_db[K_DEST] == DEST
        assert rt.state_db[K_ACCT] == ACCT
        assert rt.state_db[K_AMOUNT] == AMOUNT

    def test_the_slot_serves_the_emission_itself(self, wasm):
        """`*(hookCtx.emitFailure)` is the inner sfEmittedTxn object, so the
        slot holds the original's own fields — no ledger-entry wrapper to
        descend through — and navigates like the applied mode's."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_OTXN] == payment_blob()

        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=rich_blob(), ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_VL_SLOT] == b"\x03abc"
        assert rt.state_db[K_OBJ_TAG] == (42).to_bytes(4, "big")

    def test_both_modes_serve_one_view_of_the_emission(self, wasm):
        """Every probe answer but the callback's own argument agrees."""
        blob = rich_blob()
        applied, failed = HookRuntime(), HookRuntime()
        applied.run_callback(wasm, emitted_tx=blob, ctx=CALLBACK_APPLIED)
        failed.run_callback(wasm, emitted_tx=blob, ctx=CALLBACK_NOT_APPLIED)
        assert applied.state_db == failed.state_db

    def test_metadata_is_still_served(self, wasm):
        """The pseudo-transaction's own application generates provisional
        metadata like any other."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_RESULT] == b"\x00"


class TestNotAppliedWithoutTheFix:
    """Before fix20261005 the host dereferenced the ltEMITTED_TXN entry the
    pseudo had already erased (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1062)
    and the node went down — there is no hook-visible outcome to serve."""

    def test_the_citations_say_what_is_claimed(self):
        from hookz.wasm import xahaud_ref as ref

        def line(path, n):
            return ref.parse_citations(f"xahaud:{path}:{n}")[0].snippet()

        apply_hook = "src/xrpld/app/hook/detail/applyHook.cpp"
        assert "fix20261005" in line(apply_hook, 1051)
        assert "emitFailure = emitFailureTxn;" in line(apply_hook, 1057)
        assert "peek(keylet::emittedTxn(" in line(apply_hook, 1062)
        assert "dereferenced null" in line(
            "src/test/app/SetHook_test.cpp", 4799)

    def test_a_failure_delivery_raises(self, wasm):
        from hookz import NodeCrash

        rt = HookRuntime()
        rt.amendments.discard("fix20261005")
        with pytest.raises(NodeCrash, match="fix20261005"):
            rt.run_callback(wasm, emitted_tx=payment_blob(),
                            ctx=CALLBACK_NOT_APPLIED)
        # Nothing ran, and nothing is left in callback shape.
        assert rt.state_db == {}
        assert rt.otxn_blob is None and rt.otxn_fields == {}
        assert rt.otxn_id_val is None and rt.emit_failure is False

    def test_an_applied_delivery_is_unaffected(self, wasm):
        rt = HookRuntime()
        rt.amendments.discard("fix20261005")
        result = rt.run_callback(wasm, emitted_tx=payment_blob(),
                                 ctx=CALLBACK_APPLIED)
        assert result.accepted
        assert rt.state_db[K_DEST] == DEST


def invoke_with_params(*params) -> bytes:
    """An emitted Invoke carrying HookParameters, as (name, value|None)."""
    from xrpl.core.binarycodec import encode

    from hookz.account import to_raddr

    entries = []
    for name, value in params:
        entry = {"HookParameterName": name.hex()}
        if value is not None:
            entry["HookParameterValue"] = value.hex()
        entries.append({"HookParameter": entry})
    return bytes.fromhex(encode({
        "TransactionType": "Invoke",
        "Account": to_raddr(ACCT),
        "HookParameters": entries,
    }))


class TestCallbackParameters:
    """`otxn_param` reads sfHookParameters off the transaction being
    applied (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1669): the
    emission when applied, the parameterless pseudo when not."""

    def test_an_applied_callback_reads_the_emissions_parameters(self, wasm):
        """A trigger's leftover tx_params must not answer for the emission."""
        rt = HookRuntime()
        rt.tx_params["CMD"] = b"trigger"
        rt.run_callback(wasm, emitted_tx=invoke_with_params(
            (b"CMD", b"\x01\x02")))
        assert rt.state_db[K_PARAM_RC] == i64buf(2)
        assert rt.state_db[K_PARAM] == b"\x01\x02"
        assert rt.tx_params["CMD"] == b"trigger", "restored after"

    def test_a_name_the_emission_lacks_does_not_exist(self, wasm):
        rt = HookRuntime()
        rt.tx_params["CMD"] = b"trigger"
        rt.run_callback(wasm, emitted_tx=invoke_with_params(
            (b"OTHER", b"\x01")))
        assert rt.state_db[K_PARAM_RC] == i64buf(hookapi.DOESNT_EXIST)

    def test_the_first_match_wins_and_a_valueless_one_does_not_exist(
            self, wasm):
        """The host returns at the first name match, value or no value
        (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1680)."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=invoke_with_params(
            (b"CMD", b"\x07"), (b"CMD", b"\x08")))
        assert rt.state_db[K_PARAM] == b"\x07"

        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=invoke_with_params(
            (b"CMD", None), (b"CMD", b"\x08")))
        assert rt.state_db[K_PARAM_RC] == i64buf(hookapi.DOESNT_EXIST)

    def test_an_emission_without_the_array_leaves_the_callers_in_place(
            self, wasm):
        """The overlay's convention at field level: what the emission does
        not carry, the caller's configuration still answers."""
        rt = HookRuntime()
        rt.tx_params["CMD"] = b"\x09"
        rt.run_callback(wasm, emitted_tx=payment_blob())
        assert rt.state_db[K_PARAM] == b"\x09"

    def test_a_failure_callback_finds_no_parameters(self, wasm):
        """The pseudo is built with sfLedgerSequence, sfTransactionHash and
        sfEmitDetails (xahaud:src/xrpld/app/misc/detail/TxQ.cpp:1657), so
        neither the emission's nor the caller's parameters are there."""
        rt = HookRuntime()
        rt.tx_params["CMD"] = b"\x09"
        rt.run_callback(wasm, emitted_tx=invoke_with_params(
            (b"CMD", b"\x01")), ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_PARAM_RC] == i64buf(hookapi.DOESNT_EXIST)


class TestNoMetadata:
    def test_none_means_prerequisite_not_met(self, wasm):
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        transaction_result=None)
        assert rt.state_db[K_META_RC] == i64buf(hookapi.PREREQUISITE_NOT_MET)
        assert K_RESULT not in rt.state_db


class TestArguments:
    def test_hashes_alone_are_enough_when_applied(self, wasm):
        """otxn_id needs only the hash. sfTransactionHash is the pseudo's
        field, not the emission's, so it is not served."""
        tx_hash = bytes(range(32))
        rt = HookRuntime()
        rt.run_callback(wasm, tx_hash=tx_hash, ctx=CALLBACK_APPLIED)
        assert rt.state_db[K_ID] == tx_hash
        assert K_HASH not in rt.state_db

    def test_a_failure_delivery_needs_the_emission(self, wasm):
        """Under fix20261005 the callback reads the original emission, and
        the ledger skips it when the original is missing
        (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1554)."""
        with pytest.raises(TypeError, match="needs emitted_tx"):
            HookRuntime().run_callback(wasm, tx_hash=bytes(range(32)),
                                       ctx=CALLBACK_NOT_APPLIED)

    def test_a_failure_delivery_does_not_serve_the_triggers_fields(self, wasm):
        """otxn_field checks presence on the emission alone
        (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1591): a field the
        trigger had and the emission lacks is DOESNT_EXIST, not the
        trigger's value. Found by a blind review of the re-pin."""
        rt = HookRuntime()
        rt.otxn_fields[hookapi.sfSourceTag] = (7).to_bytes(4, "big")
        rt.run_callback(wasm, emitted_tx=payment_blob(), ctx=CALLBACK_NOT_APPLIED)
        assert K_TAG not in rt.state_db
        assert rt.otxn_fields[hookapi.sfSourceTag] == (7).to_bytes(4, "big"), \
            "the caller's entry is restored after the delivery"

    def test_neither_blob_nor_hash_is_an_error(self, wasm):
        with pytest.raises(TypeError, match="emitted_tx"):
            HookRuntime().run_callback(wasm)

    def test_a_malformed_tx_hash_is_refused(self, wasm):
        """A short or long hash is a delivery no ledger can produce."""
        for bad in (b"abc", bytes(31), bytes(33)):
            with pytest.raises(ValueError, match="32-byte Hash256"):
                HookRuntime().run_callback(
                    wasm, emitted_tx=payment_blob(), tx_hash=bad)

    def test_a_malformed_otxn_id_val_fails_loudly(self, wasm):
        """Setting the serving field directly bypasses run_callback's gate;
        the handler itself must refuse rather than let otxn_id and
        otxn_field(sfTransactionHash) disagree about one Hash256."""
        for bad in (b"abc", bytes(33)):
            rt = HookRuntime()
            rt.otxn_id_val = bad
            result = rt.run(wasm, export="cbak", arg=0)
            assert result.error is not None
            assert "32 bytes" in str(result.error)


class TestRestoration:
    def test_the_runtime_is_not_left_in_callback_shape(self, wasm):
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(source_tag=777),
                        ctx=CALLBACK_NOT_APPLIED)
        assert rt.otxn_blob is None
        assert rt.otxn_type == 0
        assert rt.otxn_id_val is None
        assert rt._callback_meta is None
        assert rt.otxn_fields == {}
        assert rt.emit_failure is False

    def test_a_plain_run_keeps_the_stub_answers(self, wasm):
        """After a callback delivery, a plain cbak run sees the sentinel id
        and PREREQUISITE_NOT_MET metadata — the pre-run_callback world."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob())
        rt.state_db.clear()
        rt.run(wasm, export="cbak", arg=0)
        assert rt.state_db[K_ID] == b"\xAB" * 32
        assert rt.state_db[K_META_RC] == i64buf(hookapi.PREREQUISITE_NOT_MET)


class TestRoundTrip:
    def test_an_emission_flows_into_its_own_callback(self, wasm):
        """`hook` emits, the test hands the emission back to `cbak` — one
        runtime, no private fields, the whole lifecycle."""
        rt = HookRuntime()
        rt.validate_emissions = False  # the fixture blob carries no EmitDetails
        rt.params["TX"] = payment_blob()
        emit_result = rt.run(wasm)
        assert emit_result.accepted
        blob = emit_result.emitted_txns[0]
        assert blob == payment_blob()

        cb_result = rt.run_callback(wasm, emitted_tx=blob,
                                    ctx=CALLBACK_APPLIED)
        assert cb_result.accepted
        assert rt.state_db[K_ID] == emitted_txn_id(blob)
        assert rt.state_db[K_TYPE] == i64buf(0)  # ttPAYMENT
        # Phase 2 meets phase 3: the journal attributes the probe's writes
        # to the cbak execution.
        assert {w.export for w in cb_result.state_writes} == {"cbak"}


# ---------------------------------------------------------------------------
# Upstream: SetHook_test.cpp test_emit_failure_callback
# ---------------------------------------------------------------------------

#: The hook from xahaud:src/test/app/SetHook_test.cpp:4791, verbatim but for
#: the raw-string wrapper. `hook` emits an Invoke that expires unapplied;
#: `cbak` asserts the failure view is the original and records its id.
UPSTREAM_EMIT_FAILURE_SOURCE = r"""
#include <stdint.h>
extern int32_t _g       (uint32_t id, uint32_t maxiter);
extern int64_t accept   (uint32_t read_ptr, uint32_t read_len, int64_t error_code);
extern int64_t rollback (uint32_t read_ptr, uint32_t read_len, int64_t error_code);
extern int64_t emit     (uint32_t write_ptr, uint32_t write_len, uint32_t read_ptr, uint32_t read_len);
extern int64_t hook_account (uint32_t write_ptr, uint32_t write_len);
extern int64_t etxn_reserve (uint32_t);
extern int64_t etxn_fee_base (uint32_t read_ptr, uint32_t read_len);
extern int64_t etxn_details (uint32_t write_ptr, uint32_t write_len);
extern int64_t ledger_seq (void);
extern int64_t otxn_id (uint32_t, uint32_t, uint32_t);
extern int64_t otxn_type (void);
extern int64_t otxn_field (uint32_t write_ptr, uint32_t write_len, uint32_t field_id);
extern int64_t state_set (uint32_t, uint32_t, uint32_t, uint32_t);
#define SBUF(x) (uint32_t)(x), sizeof(x)
#define ASSERT(x)\
    if (!(x))\
        rollback((uint32_t)#x, sizeof(#x), __LINE__);
#define DOESNT_EXIST (-5)
#define ttINVOKE 99
#define sfAccount ((8U << 16U) + 1U)
#define sfLedgerSequence ((2U << 16U) + 6U)

uint8_t key[32] = { [31] = 1U };

// an Invoke from the hook account, emitted with a callback
uint8_t txn[229] =
{
    /* size, upto, field name               */
    /*    3,    0, tt = Invoke              */   0x12U, 0x00U, 0x63U,
    /*    5,    3, flags                    */   0x22U, 0x00U, 0x00U, 0x00U, 0x00U,
    /*    5,    8, sequence                 */   0x24U, 0x00U, 0x00U, 0x00U, 0x00U,
    /*    6,   13, firstledgersequence      */   0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,
    /*    6,   19, lastledgersequence       */   0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,
    /*    9,   25, fee                      */   0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    /*   35,   34, signingpubkey            */   0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    /*   22,   69, account                  */   0x81U, 0x14U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    /*  138,   91, emit details             */
    /*    0,  229,                          */
};
#define FLS_OUT (txn + 15U)
#define LLS_OUT (txn + 21U)
#define FEE_OUT (txn + 26U)
#define ACCOUNT_OUT (txn + 71U)
#define EMIT_OUT (txn + 91U)
#define SET_UINT32(ptr, value)\
    {\
        uint32_t v = (value);\
        (ptr)[0] = v >> 24U; (ptr)[1] = v >> 16U; (ptr)[2] = v >> 8U; (ptr)[3] = v;\
    }
#define SET_NATIVE_AMOUNT(ptr, amount)\
    {\
        uint64_t a = (amount);\
        (ptr)[0] = 0x40U + ((a >> 56U) & 0x3FU);\
        (ptr)[1] = a >> 48U; (ptr)[2] = a >> 40U; (ptr)[3] = a >> 32U;\
        (ptr)[4] = a >> 24U; (ptr)[5] = a >> 16U; (ptr)[6] = a >> 8U; (ptr)[7] = a;\
    }
#define ACC_EQ(a, b)\
    (*(uint64_t*)(a) == *(uint64_t*)(b) &&\
     *(uint64_t*)((a) + 8U) == *(uint64_t*)((b) + 8U) &&\
     *(uint32_t*)((a) + 16U) == *(uint32_t*)((b) + 16U))

int64_t cbak(uint32_t r)
{
    _g(1,1);

    // 1 = the emitted txn failed (ttEMIT_FAILURE)
    ASSERT(r == 1);

    // the otxn is the original emitted txn, not the pseudo
    ASSERT(otxn_type() == ttINVOKE);

    uint8_t me[20];
    ASSERT(hook_account(SBUF(me)) == 20);
    uint8_t acc[20];
    ASSERT(otxn_field(SBUF(acc), sfAccount) == 20);
    ASSERT(ACC_EQ(acc, me));

    // carried by the pseudo but not by the emitted txn
    ASSERT(otxn_field(0, 0, sfLedgerSequence) == DOESNT_EXIST);

    // record the id of the emitted txn that failed
    uint8_t id[32];
    ASSERT(otxn_id(SBUF(id), 0) == 32);
    ASSERT(state_set(SBUF(id), SBUF(key)) == 32);

    return accept(0,0,0);
}

int64_t hook(uint32_t r)
{
    _g(1,1);

    ASSERT(etxn_reserve(1) == 1);

    // FirstLedgerSequence is the current ledger, so by the time
    // the emission directory is processed for the next ledger it
    // has already passed: the txn is never applied and expires
    // once LastLedgerSequence is behind the ledger
    uint32_t seq = (uint32_t)ledger_seq();
    SET_UINT32(FLS_OUT, seq);
    SET_UINT32(LLS_OUT, seq + 1);
    ASSERT(hook_account(ACCOUNT_OUT, 20) == 20);
    ASSERT(etxn_details(EMIT_OUT, 138U) == 138);
    int64_t fee = etxn_fee_base(SBUF(txn));
    ASSERT(fee > 0);
    SET_NATIVE_AMOUNT(FEE_OUT, fee);

    uint8_t emithash[32];
    ASSERT(emit(SBUF(emithash), SBUF(txn)) == 32);

    return accept(0,0,0);
}
"""

ALICE = bytes(range(0xA0, 0xB4))


@pytest.fixture(scope="module")
def upstream_wasm(tmp_path_factory):
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    config = load_config()
    if not (config.wasi_sdk / "bin" / "clang").exists():
        pytest.skip("wasi-sdk not found")
    source = tmp_path_factory.mktemp("emit_failure") / "emit_failure.c"
    source.write_text(UPSTREAM_EMIT_FAILURE_SOURCE)
    return compile_hook(source, None, config)


class TestUpstreamEmitFailureCallback:
    """SetHook_test.cpp test_emit_failure_callback, run on hookz: emit,
    let the emission fail, deliver the failure, and find the callback ran
    to accept() with the original emitted transaction in view."""

    def _emit(self, wasm) -> tuple[HookRuntime, bytes]:
        rt = HookRuntime()
        rt.hook_account = ALICE
        emitted = rt.run(wasm)
        assert emitted.accepted, emitted.return_msg_str
        assert rt.emission_rejections == []
        (blob,) = emitted.emitted_txns
        return rt, blob

    def test_the_callback_sees_the_original_and_records_its_id(
            self, upstream_wasm):
        rt, blob = self._emit(upstream_wasm)
        result = rt.run_callback(upstream_wasm, emitted_tx=blob,
                                 ctx=CALLBACK_NOT_APPLIED)
        # HookReturnCode 0, HookResult 3 (accept): every ASSERT held.
        assert result.accepted, (result.return_msg_str, result.return_code)
        assert result.return_code == 0
        assert rt.state_db[bytes(31) + b"\x01"] == emitted_txn_id(blob)

    def test_without_the_fix_the_failure_cannot_be_delivered(
            self, upstream_wasm):
        """Upstream runs this only under fix20261005 because the unfixed
        callback takes the process down."""
        from hookz import NodeCrash

        rt, blob = self._emit(upstream_wasm)
        rt.amendments.discard("fix20261005")
        with pytest.raises(NodeCrash):
            rt.run_callback(upstream_wasm, emitted_tx=blob,
                            ctx=CALLBACK_NOT_APPLIED)
