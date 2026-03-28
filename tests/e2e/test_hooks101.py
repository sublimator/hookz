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
