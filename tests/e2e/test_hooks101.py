"""E2E tests for XahauHooks101 example hooks.

These are community teaching hooks from github.com/Handy4ndy/XahauHooks101.
Tests exercise basic hook patterns: accept/reject, state, parameters.
"""

import struct

import pytest

from hookz import hookapi
from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl


HOOK_ACCID = b"\xAA" * 20
SENDER_ACCID = b"\xBB" * 20


@pytest.fixture
def rt():
    r = HookRuntime()
    r.hook_account = HOOK_ACCID
    r.otxn_account = SENDER_ACCID
    r.otxn_type = hookapi.ttPAYMENT
    return r


def _set_xah_amount(rt, drops: int):
    """Set sfAmount as 8-byte XAH amount on otxn (for otxn_field)."""
    # XAH amount: 8 bytes, bit 62 set for positive
    buf = struct.pack(">Q", 0x4000000000000000 | drops)
    rt._otxn_amount = buf


# ---------------------------------------------------------------------------
# Basic Native — Accept/Reject incoming XAH
# ---------------------------------------------------------------------------

class TestAcceptIncomingXah:
    """accept_incoming_xah.c: accepts incoming XAH, rejects incoming IOU."""

    def test_outgoing_accepted(self, accept_incoming_xah_hook, rt):
        rt.otxn_account = rt.hook_account  # outgoing
        result = rt.run(accept_incoming_xah_hook)
        assert result.accepted
        assert b"Outgoing" in result.return_msg

    def test_incoming_xah_accepted(self, accept_incoming_xah_hook, rt):
        """Incoming XAH (sfAmount = 8 bytes) → accepted."""
        # otxn_field(amount, 48, sfAmount) returns 8 for XAH
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_xah_to_memory(rt, w, 1_000_000) if fid == hookapi.sfAmount
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(accept_incoming_xah_hook)
        assert result.accepted
        assert b"XAH payment accepted" in result.return_msg

    def test_incoming_iou_rejected(self, accept_incoming_xah_hook, rt):
        """Incoming IOU (sfAmount = 48 bytes) → rejected."""
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_iou_to_memory(rt, w) if fid == hookapi.sfAmount
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(accept_incoming_xah_hook)
        assert result.rejected
        assert b"IOU" in result.return_msg


class TestRejectIncomingXah:
    """reject_incoming_xah.c: rejects incoming XAH, accepts outgoing."""

    def test_outgoing_rejected(self, reject_incoming_xah_hook, rt):
        """This hook rejects outgoing payments."""
        rt.otxn_account = rt.hook_account
        result = rt.run(reject_incoming_xah_hook)
        assert result.rejected
        assert b"Outgoing" in result.return_msg

    def test_incoming_xah_rejected(self, reject_incoming_xah_hook, rt):
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_xah_to_memory(rt, w, 1_000_000) if fid == hookapi.sfAmount
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(reject_incoming_xah_hook)
        assert result.rejected


# ---------------------------------------------------------------------------
# Basic State
# ---------------------------------------------------------------------------

class TestStateCounter:
    """basic_state_counter.c: increments counter on each Payment."""

    def test_first_payment_sets_counter_to_1(self, state_counter_hook, rt):
        result = rt.run(state_counter_hook)
        assert result.accepted
        cnt = rt.state_db.get(b"CNT")
        assert cnt is not None
        assert struct.unpack(">Q", cnt)[0] == 1

    def test_second_payment_increments(self, state_counter_hook, rt):
        # Pre-seed counter at 5
        rt.state_db[b"CNT"] = struct.pack(">Q", 5)
        result = rt.run(state_counter_hook)
        assert result.accepted
        assert struct.unpack(">Q", rt.state_db[b"CNT"])[0] == 6

    def test_invoke_by_owner_updates_counter(self, state_counter_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account  # owner
        rt.params[b"CNT"] = struct.pack(">Q", 42)
        # Pre-seed counter at 5 — should be overwritten, not incremented
        rt.state_db[b"CNT"] = struct.pack(">Q", 5)
        result = rt.run(state_counter_hook)
        assert result.accepted
        assert b"manually updated" in result.return_msg
        assert struct.unpack(">Q", rt.state_db[b"CNT"])[0] == 42  # 42, not 6

    def test_invoke_by_non_owner_rejected(self, state_counter_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        result = rt.run(state_counter_hook)
        assert result.rejected
        assert b"Only hook owner" in result.return_msg

    def test_invoke_missing_param_rejected(self, state_counter_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        # No CNT param
        result = rt.run(state_counter_hook)
        assert result.rejected
        assert b"8 bytes" in result.return_msg

    def test_non_payment_non_invoke_accepted(self, state_counter_hook, rt):
        rt.otxn_type = 20  # some other tt
        result = rt.run(state_counter_hook)
        assert result.accepted
        assert b"not handled" in result.return_msg


class TestStateToggle:
    """basic_state_toggle.c: on/off toggle via Invoke."""

    def test_invoke_enable(self, state_toggle_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"TGL"] = b"\x01"
        result = rt.run(state_toggle_hook)
        assert result.accepted
        assert rt.state_db[b"TGL"] == b"\x01"

    def test_invoke_disable(self, state_toggle_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"TGL"] = b"\x00"
        result = rt.run(state_toggle_hook)
        assert result.accepted
        assert rt.state_db[b"TGL"] == b"\x00"

    def test_invoke_non_owner_rejected(self, state_toggle_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.params[b"TGL"] = b"\x01"
        result = rt.run(state_toggle_hook)
        assert result.rejected

    def test_payment_when_enabled(self, state_toggle_hook, rt):
        rt.state_db[b"TGL"] = b"\x01"
        result = rt.run(state_toggle_hook)
        assert result.accepted

    def test_payment_when_disabled(self, state_toggle_hook, rt):
        rt.state_db[b"TGL"] = b"\x00"
        result = rt.run(state_toggle_hook)
        assert result.accepted


# ---------------------------------------------------------------------------
# Helpers for otxn_field amount override
# ---------------------------------------------------------------------------

def _default_otxn_field(rt, write_ptr, write_len, field_id):
    from hookz.handlers.otxn import otxn_field
    return otxn_field(rt, write_ptr, write_len, field_id)


def _write_xah_to_memory(rt, write_ptr, drops):
    """Write 8-byte XAH amount and return 8."""
    buf = struct.pack(">Q", 0x4000000000000000 | drops)
    rt._write_memory(write_ptr, buf)
    return 8


def _extract_uri(txn_bytes: bytes) -> bytes:
    """Extract the URI from an emitted Remit transaction.

    The txn template has: offset 234: E0 5C 75 <len> <uri_data> E1
    So the URI starts at offset 237: first byte is VL length, then data.
    """
    uri_offset = 237
    uri_len = txn_bytes[uri_offset]
    return txn_bytes[uri_offset + 1 : uri_offset + 1 + uri_len]


def _write_iou_to_memory(rt, write_ptr):
    """Write 48-byte IOU amount and return 48."""
    buf = b"\xD5\x03\x8D\x7E\xA4\xC6\x80\x00" + b"\x00" * 20 + b"\x01" * 20
    rt._write_memory(write_ptr, buf)
    return 48


# ---------------------------------------------------------------------------
# Remit IOU — Multi-recipient IOU remit via invoke state
# ---------------------------------------------------------------------------

ACC1 = b"\x11" * 20
ACC2 = b"\x22" * 20
USD_CURRENCY = b"\x00" * 12 + b"USD" + b"\x00" * 5
ISSUER = b"\x33" * 20


def _setup_remit_state(rt, amt_in=10, amt_out=100):
    """Pre-seed all state keys for the multi IOU remit hook."""
    rt.state_db[b"AMT_IN"] = struct.pack(">Q", amt_in)
    rt.state_db[b"AMT_OUT"] = struct.pack(">Q", amt_out)
    rt.state_db[b"F_ACC1"] = ACC1
    rt.state_db[b"F_ACC2"] = ACC2
    rt.state_db[b"CURRENCY"] = USD_CURRENCY
    rt.state_db[b"ISSUER"] = ISSUER


class TestMultiIouRemitInvoke:
    """invoke_multi_iou_remit.c — setting parameters via Invoke."""

    def test_set_amt_in(self, multi_iou_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"AMT_IN"] = struct.pack(">Q", 50)
        result = rt.run(multi_iou_remit_hook)
        assert result.accepted
        assert b"AMT_IN set" in result.return_msg
        assert rt.state_db[b"AMT_IN"] == struct.pack(">Q", 50)

    def test_set_acc1(self, multi_iou_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"F_ACC1"] = ACC1
        result = rt.run(multi_iou_remit_hook)
        assert result.accepted
        assert b"F_ACC1 set" in result.return_msg

    def test_acc1_cannot_be_hook(self, multi_iou_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"F_ACC1"] = rt.hook_account  # same as hook → rejected
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"cannot match" in result.return_msg

    def test_non_owner_rejected(self, multi_iou_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.params[b"AMT_IN"] = struct.pack(">Q", 50)
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"Only hook owner" in result.return_msg

    def test_no_params_rejected(self, multi_iou_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"No valid parameters" in result.return_msg


class TestMultiIouRemitPayment:
    """invoke_multi_iou_remit.c — payment triggers dual IOU remit."""

    def test_outgoing_passes(self, multi_iou_remit_hook, rt):
        rt.otxn_account = rt.hook_account
        result = rt.run(multi_iou_remit_hook)
        assert result.accepted
        assert b"Outgoing" in result.return_msg

    def test_missing_state_rejected(self, multi_iou_remit_hook, rt):
        """No state configured → rejected."""
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_xah_to_memory(rt, w, 10_000_000) if fid == hookapi.sfAmount
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"not set" in result.return_msg

    def test_wrong_amount_rejected(self, multi_iou_remit_hook, rt):
        """Payment doesn't match AMT_IN → rejected."""
        _setup_remit_state(rt, amt_in=10)
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_xah_to_memory(rt, w, 5_000_000) if fid == hookapi.sfAmount  # 5 XAH, need 10
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"doesn't match" in result.return_msg

    def test_matching_amount_emits_two_remits(self, multi_iou_remit_hook, rt):
        """Exact XAH payment → emits 2 IOU Remits to different accounts."""
        _setup_remit_state(rt, amt_in=10, amt_out=100)
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_xah_to_memory(rt, w, 10_000_000) if fid == hookapi.sfAmount  # 10 XAH
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(multi_iou_remit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 2

        # Both should be ttREMIT (0x005F)
        for txn in rt.emitted_txns:
            assert txn[0:3] == b"\x12\x00\x5F", f"Expected ttREMIT, got {txn[0:3].hex()}"

        # Source account (offset 71, 20 bytes) should be hook account
        assert rt.emitted_txns[0][71:91] == rt.hook_account
        assert rt.emitted_txns[1][71:91] == rt.hook_account

        # Destinations (offset 93, 20 bytes) should be ACC1 and ACC2
        assert rt.emitted_txns[0][93:113] == ACC1
        assert rt.emitted_txns[1][93:113] == ACC2

    def test_same_acc1_acc2_rejected(self, multi_iou_remit_hook, rt):
        """F_ACC1 == F_ACC2 → rejected."""
        _setup_remit_state(rt)
        rt.state_db[b"F_ACC2"] = ACC1  # same as ACC1
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_xah_to_memory(rt, w, 10_000_000) if fid == hookapi.sfAmount
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"cannot match" in result.return_msg

    def test_iou_payment_rejected(self, multi_iou_remit_hook, rt):
        """IOU payment → rejected (only XAH accepted)."""
        _setup_remit_state(rt)
        rt.handlers["otxn_field"] = lambda w, wl, fid: (
            _write_iou_to_memory(rt, w) if fid == hookapi.sfAmount
            else _default_otxn_field(rt, w, wl, fid)
        )
        result = rt.run(multi_iou_remit_hook)
        assert result.rejected
        assert b"Non-XAH" in result.return_msg


# ---------------------------------------------------------------------------
# Remit URI — Sequential URI token minting
# ---------------------------------------------------------------------------

def _setup_uri_state(rt, prefix=b"ipfs://Qm123/", count=10, mint=2):
    """Pre-seed state for the URI mint hook."""
    rt.state_db[b"PREFIX"] = prefix
    rt.state_db[b"COUNT"] = struct.pack(">Q", count)
    rt.state_db[b"TOTAL"] = struct.pack(">Q", count)
    rt.state_db[b"MINT"] = struct.pack(">Q", mint)


class TestMultiUriRemitInvoke:
    """invoke_multi_uri_remit.c — owner configures via Invoke."""

    def test_set_prefix(self, multi_uri_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"PREFIX"] = b"ipfs://QmHash/"
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted
        assert rt.state_db[b"PREFIX"] == b"ipfs://QmHash/"

    def test_set_count(self, multi_uri_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"COUNT"] = struct.pack(">Q", 100)
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted
        assert struct.unpack(">Q", rt.state_db[b"COUNT"])[0] == 100
        # TOTAL should also be set
        assert struct.unpack(">Q", rt.state_db[b"TOTAL"])[0] == 100

    def test_set_mint_capped_at_5(self, multi_uri_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"MINT"] = struct.pack(">Q", 10)  # over 5
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted
        assert struct.unpack(">Q", rt.state_db[b"MINT"])[0] == 5

    def test_non_owner_rejected(self, multi_uri_remit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.params[b"PREFIX"] = b"ipfs://test/"
        result = rt.run(multi_uri_remit_hook)
        assert result.rejected
        assert b"Only hook owner" in result.return_msg


class TestMultiUriRemitPayment:
    """invoke_multi_uri_remit.c — payments mint sequential URITokens."""

    def test_missing_prefix_rejected(self, multi_uri_remit_hook, rt):
        result = rt.run(multi_uri_remit_hook)
        assert result.rejected
        assert b"No URI prefix" in result.return_msg

    def test_no_remaining_rejected(self, multi_uri_remit_hook, rt):
        _setup_uri_state(rt, count=0)
        result = rt.run(multi_uri_remit_hook)
        assert result.rejected
        assert b"No NFTs remaining" in result.return_msg

    def test_mints_sequential_tokens(self, multi_uri_remit_hook, rt):
        """Mint 2 tokens with prefix 'ipfs://Qm/' → emits 2 Remits with sequential URIs."""
        _setup_uri_state(rt, prefix=b"ipfs://Qm/", count=10, mint=2)
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 2

        for txn in rt.emitted_txns:
            # ttREMIT
            assert txn[0:3] == b"\x12\x00\x5F"
            # Source = hook account (offset 76)
            assert txn[76:96] == rt.hook_account
            # Destination = sender (offset 98)
            assert txn[98:118] == SENDER_ACCID

        # URIs should contain sequential numbers — find them in the emitted bytes
        # The URI is after offset 237 in the txn template, format: len + data + 0xE1
        uri1 = _extract_uri(rt.emitted_txns[0])
        uri2 = _extract_uri(rt.emitted_txns[1])
        assert uri1.endswith(b"000001.json")
        assert uri2.endswith(b"000002.json")
        assert uri1.startswith(b"ipfs://Qm/")
        assert uri2.startswith(b"ipfs://Qm/")

        # Count decremented by 2
        assert struct.unpack(">Q", rt.state_db[b"COUNT"])[0] == 8

    def test_mint_1_token(self, multi_uri_remit_hook, rt):
        _setup_uri_state(rt, prefix=b"test/", count=5, mint=1)
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 1
        uri = _extract_uri(rt.emitted_txns[0])
        assert uri == b"test/000001.json"
        assert struct.unpack(">Q", rt.state_db[b"COUNT"])[0] == 4

    def test_mint_limited_by_remaining(self, multi_uri_remit_hook, rt):
        """Mint=3 but only 1 remaining → only 1 emitted."""
        _setup_uri_state(rt, prefix=b"x/", count=1, mint=3)
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 1
        uri = _extract_uri(rt.emitted_txns[0])
        assert uri == b"x/000001.json"
        assert struct.unpack(">Q", rt.state_db[b"COUNT"])[0] == 0

    def test_other_tt_accepted(self, multi_uri_remit_hook, rt):
        """Non-payment, non-invoke → accepted."""
        rt.otxn_type = 20  # random type
        result = rt.run(multi_uri_remit_hook)
        assert result.accepted


# ---------------------------------------------------------------------------
# Emit Invoke — Multi-destination invoke emitter
# ---------------------------------------------------------------------------

DST1 = b"\xD1" * 20
DST2 = b"\xD2" * 20
DST3 = b"\xD3" * 20


class TestMultiInvokeEmitConfig:
    """invoke_multi_invoke_emit.c — owner sets DST1/2/3 via Invoke."""

    def test_set_dst1(self, multi_invoke_emit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"DST1"] = DST1
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert rt.state_db[b"DST1"] == DST1

    def test_set_all_three(self, multi_invoke_emit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"DST1"] = DST1
        rt.params[b"DST2"] = DST2
        rt.params[b"DST3"] = DST3
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert rt.state_db[b"DST1"] == DST1
        assert rt.state_db[b"DST2"] == DST2
        assert rt.state_db[b"DST3"] == DST3

    def test_reset_clears_all(self, multi_invoke_emit_hook, rt):
        rt.state_db[b"DST1"] = DST1
        rt.state_db[b"DST2"] = DST2
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        rt.params[b"RSET"] = b"\x01"
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert b"reset" in result.return_msg
        assert rt.state_db[b"DST1"] == b"\x00" * 20
        assert rt.state_db[b"DST2"] == b"\x00" * 20
        assert rt.state_db[b"DST3"] == b"\x00" * 20

    def test_non_owner_rejected(self, multi_invoke_emit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.params[b"DST1"] = DST1
        result = rt.run(multi_invoke_emit_hook)
        assert result.rejected
        assert b"Only hook owner" in result.return_msg

    def test_no_params_rejected(self, multi_invoke_emit_hook, rt):
        rt.otxn_type = hookapi.ttINVOKE
        rt.otxn_account = rt.hook_account
        result = rt.run(multi_invoke_emit_hook)
        assert result.rejected
        assert b"No DST set" in result.return_msg


class TestMultiInvokeEmitPayment:
    """invoke_multi_invoke_emit.c — payment emits invokes to DST1/2/3."""

    def test_no_destinations_set(self, multi_invoke_emit_hook, rt):
        result = rt.run(multi_invoke_emit_hook)
        assert result.rejected
        assert b"No destinations" in result.return_msg

    def test_emit_to_one_destination(self, multi_invoke_emit_hook, rt):
        rt.state_db[b"DST1"] = DST1
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 1
        # ttINVOKE = 0x0063
        assert rt.emitted_txns[0][0:3] == b"\x12\x00\x63"
        # Source = hook account (offset 76)
        assert rt.emitted_txns[0][76:96] == rt.hook_account
        # Destination = DST1 (offset 98)
        assert rt.emitted_txns[0][98:118] == DST1

    def test_emit_to_three_destinations(self, multi_invoke_emit_hook, rt):
        rt.state_db[b"DST1"] = DST1
        rt.state_db[b"DST2"] = DST2
        rt.state_db[b"DST3"] = DST3
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 3
        # Each emitted to the correct destination
        assert rt.emitted_txns[0][98:118] == DST1
        assert rt.emitted_txns[1][98:118] == DST2
        assert rt.emitted_txns[2][98:118] == DST3
        # All ttINVOKE
        for txn in rt.emitted_txns:
            assert txn[0:3] == b"\x12\x00\x63"

    def test_zero_dst_skipped(self, multi_invoke_emit_hook, rt):
        """DST1 set, DST2 all zeros → only 1 emit."""
        rt.state_db[b"DST1"] = DST1
        rt.state_db[b"DST2"] = b"\x00" * 20
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert len(rt.emitted_txns) == 1
        assert rt.emitted_txns[0][98:118] == DST1

    def test_non_payment_skipped(self, multi_invoke_emit_hook, rt):
        rt.otxn_type = 20  # not payment, not invoke
        result = rt.run(multi_invoke_emit_hook)
        assert result.accepted
        assert b"Not a payment" in result.return_msg
        assert len(rt.emitted_txns) == 0
