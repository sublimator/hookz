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
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:1908)."""

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
    def test_the_pseudo_transaction_shape(self, wasm):
        blob = payment_blob(source_tag=777)
        rt = HookRuntime()
        rt.ledger_seq_val = 100_001
        result = rt.run_callback(wasm, emitted_tx=blob,
                                 ctx=CALLBACK_NOT_APPLIED)
        assert result.accepted

        assert rt.state_db[K_SEQ] == (100_001).to_bytes(4, "big")
        assert rt.state_db[K_HASH] == emitted_txn_id(blob)
        assert rt.state_db[K_ID] == emitted_txn_id(blob)

    def test_the_original_is_not_directly_readable(self, wasm):
        """The dead-restore-path story: a cbak that opens by reading
        sfDestination takes its early exit on every failure, and serving
        the field would hide that."""
        rt = HookRuntime()
        rt.otxn_fields[hookapi.sfDestination] = DEST
        rt.run_callback(wasm, emitted_tx=payment_blob(source_tag=777),
                        ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_DEST_RC] == i64buf(hookapi.DOESNT_EXIST)
        assert K_TAG not in rt.state_db

    def test_the_slot_serves_the_ledger_entry_wrapper(self, wasm):
        """On failure the slotted object is the emitted-txn ledger entry —
        the original nested under sfEmittedTxn — so a repair path must
        descend through it, exactly as on chain."""
        blob = payment_blob()
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=blob, ctx=CALLBACK_NOT_APPLIED)
        wrapper = serialize_fields({hookapi.sfEmittedTxn: blob + b"\xE1"})
        assert rt.state_db[K_OTXN] == wrapper

    def test_metadata_is_still_served(self, wasm):
        """The pseudo-transaction's own application generates provisional
        metadata like any other."""
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_RESULT] == b"\x00"


class TestNoMetadata:
    def test_none_means_prerequisite_not_met(self, wasm):
        rt = HookRuntime()
        rt.run_callback(wasm, emitted_tx=payment_blob(),
                        transaction_result=None)
        assert rt.state_db[K_META_RC] == i64buf(hookapi.PREREQUISITE_NOT_MET)
        assert K_RESULT not in rt.state_db


class TestArguments:
    def test_hashes_alone_are_enough(self, wasm):
        tx_hash = bytes(range(32))
        rt = HookRuntime()
        rt.run_callback(wasm, tx_hash=tx_hash, ctx=CALLBACK_NOT_APPLIED)
        assert rt.state_db[K_ID] == tx_hash
        assert rt.state_db[K_HASH] == tx_hash

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
