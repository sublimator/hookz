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
        result = rt.run(state_counter_hook)
        assert result.accepted
        assert b"manually updated" in result.return_msg
        assert struct.unpack(">Q", rt.state_db[b"CNT"])[0] == 42

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
