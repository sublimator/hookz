"""E2E tests for balance_gate.c — exercises keylet → slot → subfield → float chain."""

import struct

import pytest

from hookz import hookapi
from hookz.ledger import account_root, account_root_keylet
from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float


ALICE = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
BOB = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"

ALICE_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")
BOB_ACCID = bytes.fromhex("f667b0ca50cc7709a220b0561b85e53a48461fa8")


@pytest.fixture
def hook(balance_gate_hook):
    return balance_gate_hook


@pytest.fixture
def rt():
    r = HookRuntime()
    r.hook_account = ALICE_ACCID
    r.otxn_account = BOB_ACCID
    r.otxn_type = hookapi.ttPAYMENT
    return r


class TestBalanceGatePass:
    """Transactions that should be accepted."""

    def test_outgoing_always_passes(self, hook, rt):
        """Outgoing txns (from hook account) always pass."""
        rt.otxn_account = rt.hook_account  # same = outgoing

        result = rt.run(hook)
        assert result.accepted
        assert b"outgoing" in result.return_msg

    def test_sender_with_sufficient_balance(self, hook, rt):
        """Sender has 50 XAH (50M drops) — well above 10 XAH minimum."""
        kl, data = account_root(BOB, Balance="50000000")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.accepted
        assert b"pass" in result.return_msg

    def test_sender_exactly_at_minimum(self, hook, rt):
        """Sender has exactly 10 XAH (10M drops) — should pass (>=)."""
        kl, data = account_root(BOB, Balance="10000000")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.accepted

    def test_sender_with_large_balance(self, hook, rt):
        """Sender has 1,000,000 XAH."""
        kl, data = account_root(BOB, Balance="1000000000000")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.accepted


class TestBalanceGateReject:
    """Transactions that should be rejected."""

    def test_sender_below_minimum(self, hook, rt):
        """Sender has 5 XAH (5M drops) — below 10 XAH minimum."""
        kl, data = account_root(BOB, Balance="5000000")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.rejected
        assert b"too low" in result.return_msg

    def test_sender_with_zero_balance(self, hook, rt):
        """Sender has 0 drops."""
        kl, data = account_root(BOB, Balance="0")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.rejected

    def test_sender_with_1_drop(self, hook, rt):
        """Sender has 1 drop — way below minimum."""
        kl, data = account_root(BOB, Balance="1")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.rejected

    def test_sender_not_in_ledger(self, hook, rt):
        """Sender's account not in rt.ledger → slot contains keylet bytes, parse fails."""
        # Don't populate ledger — slot_set stores the raw keylet,
        # slot_subfield can't parse it as an STObject
        result = rt.run(hook)
        assert result.rejected


class TestBalanceGateCustomMinimum:
    """Custom minimum balance via hook parameter."""

    def test_custom_min_100_xah(self, hook, rt):
        """Set MIN_BAL to 100 XAH (100M drops). Sender has 50 XAH → reject."""
        min_xfl = float_to_xfl(100_000_000.0)  # 100M drops
        rt.params[b"MIN_BAL"] = struct.pack("<q", min_xfl)

        kl, data = account_root(BOB, Balance="50000000")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.rejected

    def test_custom_min_1_xah(self, hook, rt):
        """Set MIN_BAL to 1 XAH (1M drops). Sender has 5 XAH → pass."""
        min_xfl = float_to_xfl(1_000_000.0)  # 1M drops
        rt.params[b"MIN_BAL"] = struct.pack("<q", min_xfl)

        kl, data = account_root(BOB, Balance="5000000")
        rt.ledger[kl] = data

        result = rt.run(hook)
        assert result.accepted
