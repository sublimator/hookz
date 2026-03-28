"""E2E tests for treasury.c — withdrawal rate-limiting + reward claiming."""

import struct

import pytest

from hookz import hookapi
from hookz.ledger import account_root
from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl


GENESIS_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")
HOOK_ACCID = bytes.fromhex("AA" * 20)
DEST_ACCID = bytes.fromhex("BB" * 20)
DEST_ADDR = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
DEST_REAL_ACCID = bytes.fromhex("f667b0ca50cc7709a220b0561b85e53a48461fa8")
INVOKER_ACCID = bytes.fromhex("CC" * 20)

AMOUNT_LIMIT_XFL = 6215967485771284480  # 10M XAH
DEFAULT_REWARD_DELAY = 6199553087261802496
DEFAULT_REWARD_RATE = 6038156834009797973


@pytest.fixture
def hook(treasury_hook):
    return treasury_hook


@pytest.fixture
def rt():
    r = HookRuntime()
    r.hook_account = HOOK_ACCID
    r.otxn_account = INVOKER_ACCID
    r.otxn_type = hookapi.ttINVOKE
    r.ledger_seq_val = 1000
    r.ledger_last_time_val = 5_000_000
    return r


def _setup_params(rt, amount_xfl=None, ledger_limit=100, dest=DEST_REAL_ACCID):
    """Set the required hook parameters A, L, D."""
    if amount_xfl is None:
        amount_xfl = float_to_xfl(1_000_000.0)  # 1M drops
    rt.params[b"A"] = struct.pack("<q", amount_xfl)
    rt.params[b"L"] = struct.pack("<I", ledger_limit)
    rt.params[b"D"] = dest
    # Put dest account in ledger so keylet lookup works
    kl, data = account_root(DEST_ADDR)
    rt.ledger[kl] = data


class TestTreasuryNonInvoke:
    """Non-invoke transactions should be rejected (HookOn misconfigured)."""

    def test_payment_rejected(self, hook, rt):
        _setup_params(rt)
        rt.otxn_type = hookapi.ttPAYMENT
        result = rt.run(hook)
        assert result.rejected
        assert b"HookOn" in result.return_msg


class TestTreasuryParamValidation:
    """Parameter validation."""

    def test_missing_amount_param(self, hook, rt):
        rt.params[b"L"] = struct.pack("<I", 100)
        rt.params[b"D"] = DEST_REAL_ACCID
        kl, data = account_root(DEST_ADDR)
        rt.ledger[kl] = data
        result = rt.run(hook)
        assert result.rejected
        assert b"Amount" in result.return_msg

    def test_missing_ledger_param(self, hook, rt):
        rt.params[b"A"] = struct.pack("<q", float_to_xfl(1000.0))
        rt.params[b"D"] = DEST_REAL_ACCID
        kl, data = account_root(DEST_ADDR)
        rt.ledger[kl] = data
        result = rt.run(hook)
        assert result.rejected
        assert b"Ledger limit" in result.return_msg

    def test_missing_dest_param(self, hook, rt):
        rt.params[b"A"] = struct.pack("<q", float_to_xfl(1000.0))
        rt.params[b"L"] = struct.pack("<I", 100)
        result = rt.run(hook)
        assert result.rejected
        assert b"Destination" in result.return_msg

    def test_negative_amount_rejected(self, hook, rt):
        _setup_params(rt, amount_xfl=float_to_xfl(-100.0))
        result = rt.run(hook)
        assert result.rejected
        assert b"Invalid amount" in result.return_msg

    def test_amount_over_limit_rejected(self, hook, rt):
        _setup_params(rt, amount_xfl=AMOUNT_LIMIT_XFL)  # exactly 10M → rejected (>=)
        result = rt.run(hook)
        assert result.rejected
        assert b"10M" in result.return_msg

    def test_ledger_limit_too_low(self, hook, rt):
        _setup_params(rt, ledger_limit=10)  # below MIN_LEDGER_LIMIT=50
        result = rt.run(hook)
        assert result.rejected
        assert b"greater than" in result.return_msg

    def test_ledger_limit_too_high(self, hook, rt):
        _setup_params(rt, ledger_limit=8_000_000)  # above MAX_LEDGER_LIMIT
        result = rt.run(hook)
        assert result.rejected
        assert b"less than" in result.return_msg

    def test_dest_not_in_ledger(self, hook, rt):
        """Destination account not in ledger → rejected."""
        rt.params[b"A"] = struct.pack("<q", float_to_xfl(1000.0))
        rt.params[b"L"] = struct.pack("<I", 100)
        rt.params[b"D"] = DEST_REAL_ACCID
        # Don't populate ledger
        result = rt.run(hook)
        assert result.rejected
        assert b"Does Not Exist" in result.return_msg


class TestTreasuryWithdraw:
    """Withdrawal flow (W parameter)."""

    def test_successful_withdrawal(self, hook, rt):
        _setup_params(rt, amount_xfl=float_to_xfl(5_000_000.0))
        rt.params[b"W"] = struct.pack("<q", float_to_xfl(1_000_000.0))  # 1M drops
        rt.ledger_seq_val = 1000
        result = rt.run(hook)
        assert result.accepted
        assert b"Released" in result.return_msg
        assert len(rt.emitted_txns) == 1
        # State should track last release ledger
        assert rt.state_db[b"LAST"] == struct.pack("<I", 1000)

    def test_withdraw_exceeds_limit(self, hook, rt):
        _setup_params(rt, amount_xfl=float_to_xfl(1_000.0))
        rt.params[b"W"] = struct.pack("<q", float_to_xfl(5_000.0))  # over limit
        result = rt.run(hook)
        assert result.rejected
        assert b"exceeds" in result.return_msg

    def test_withdraw_too_soon(self, hook, rt):
        """Withdrawal before ledger cooldown → rejected."""
        _setup_params(rt, ledger_limit=100)
        rt.params[b"W"] = struct.pack("<q", float_to_xfl(1_000.0))
        rt.state_db[b"LAST"] = struct.pack("<I", 950)  # released at ledger 950
        rt.ledger_seq_val = 1000  # only 50 ledgers elapsed, need 100
        result = rt.run(hook)
        assert result.rejected
        assert b"must wait" in result.return_msg.lower()

    def test_withdraw_after_cooldown(self, hook, rt):
        """Withdrawal after cooldown → accepted."""
        _setup_params(rt, ledger_limit=100)
        rt.params[b"W"] = struct.pack("<q", float_to_xfl(1_000.0))
        rt.state_db[b"LAST"] = struct.pack("<I", 800)  # released at ledger 800
        rt.ledger_seq_val = 1000  # 200 ledgers elapsed, need 100
        result = rt.run(hook)
        assert result.accepted
        assert b"Released" in result.return_msg

    def test_missing_withdraw_amount(self, hook, rt):
        """No W or C parameter → asks for amount."""
        _setup_params(rt)
        result = rt.run(hook)
        assert result.rejected
        assert b"Specify" in result.return_msg


class TestTreasuryClaim:
    """Reward claim flow (C parameter)."""

    def test_first_claim_setup(self, hook, rt):
        """First claim (no sfRewardAccumulator) → setup, emits ClaimReward."""
        _setup_params(rt)
        rt.params[b"C"] = b"\x01"
        # Put hook account in ledger for the claim keylet lookup
        kl, data = account_root("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")
        rt.ledger[kl] = data
        # No sfRewardAccumulator → first time setup
        result = rt.run(hook)
        assert result.accepted
        assert b"Setup Passed" in result.return_msg
        assert len(rt.emitted_txns) == 1
