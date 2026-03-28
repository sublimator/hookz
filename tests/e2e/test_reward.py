"""E2E tests for reward.c — Xahau reward distribution hook."""

import struct

import pytest

from hookz import hookapi
from hookz.ledger import account_root
from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float


GENESIS_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")
CLAIMER_ADDR = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
CLAIMER_ACCID = bytes.fromhex("f667b0ca50cc7709a220b0561b85e53a48461fa8")
MEMBER_0 = bytes.fromhex("01" * 20)

# XFL constants from reward.c
DEFAULT_REWARD_DELAY = 6199553087261802496  # 2,600,000 seconds
DEFAULT_REWARD_RATE = 6038156834009797973   # ~0.00333333

# ttCLAIM_REWARD = 98
TT_CLAIM_REWARD = 98


@pytest.fixture
def hook(reward_hook):
    return reward_hook


@pytest.fixture
def rt():
    r = HookRuntime()
    r.hook_account = GENESIS_ACCID
    r.otxn_account = CLAIMER_ACCID
    r.otxn_type = TT_CLAIM_REWARD
    r.ledger_seq_val = 1000
    r.ledger_last_time_val = 3_000_000  # well past the delay
    return r


def _setup_reward_state(rt):
    """Set up governance state for rewards."""
    rt.state_db[b"RR"] = struct.pack("<q", DEFAULT_REWARD_RATE)
    rt.state_db[b"RD"] = struct.pack("<q", DEFAULT_REWARD_DELAY)
    rt.state_db[b"MC"] = bytes([3])
    for i in range(3):
        member = bytes([i + 1] * 20)
        rt.state_db[bytes([i])] = member
        rt.state_db[member] = bytes([i])


def _setup_claimer_account(rt, balance_drops=100_000_000_000, reward_time=0,
                           reward_first=1, reward_last=900, accumulator=0):
    """Populate claimer's AccountRoot in the ledger with reward fields."""
    kl, data = account_root(CLAIMER_ADDR, Balance=str(balance_drops))
    rt.ledger[kl] = data

    # The hook navigates: slot_subfield(1, sfRewardAccumulator, 2)
    # Then reads sfRewardLgrFirst, sfRewardLgrLast, sfBalance, sfRewardTime
    # We need to provide these via slot overrides since AccountRoot from xrpl-py
    # won't have these Xahau-specific fields
    rt._slot_overrides[f"slot_subfield:1:{hookapi.sfRewardAccumulator}"] = 2
    rt._slot_overrides[f"slot_subfield:1:{hookapi.sfRewardLgrFirst}"] = 3
    rt._slot_overrides[f"slot_subfield:1:{hookapi.sfRewardLgrLast}"] = 4
    rt._slot_overrides[f"slot_subfield:1:{hookapi.sfBalance}"] = 5
    rt._slot_overrides[f"slot_subfield:1:{hookapi.sfRewardTime}"] = 6

    # slot(0, 0, N) returns the value as int64 (write_ptr=0, write_len=0)
    rt._slot_overrides["slot_data:2"] = struct.pack(">q", accumulator)
    rt._slot_overrides["slot_data:3"] = struct.pack(">q", reward_first)
    rt._slot_overrides["slot_data:4"] = struct.pack(">q", reward_last)
    # Balance is stored as big-endian drops with top bits for XRP flag
    rt._slot_overrides["slot_data:5"] = struct.pack(">Q", 0x4000000000000000 | balance_drops)
    rt._slot_overrides["slot_data:6"] = struct.pack(">q", reward_time)

    # otxn_slot(10) and slot_subfield(10, sfFee, 11) for fee refund
    rt._slot_overrides[f"slot_subfield:10:{hookapi.sfFee}"] = 11
    rt._slot_overrides["slot_data:11"] = struct.pack(">Q", 0x4000000000000000 | 12)  # 12 drops fee


class TestRewardPassthrough:
    """Non-claim transactions and outgoing should pass."""

    def test_non_claim_passes(self, hook, rt):
        rt.otxn_type = hookapi.ttPAYMENT
        result = rt.run(hook)
        assert result.accepted
        assert b"Passing non-claim" in result.return_msg

    def test_outgoing_passes(self, hook, rt):
        rt.otxn_account = GENESIS_ACCID  # outgoing
        result = rt.run(hook)
        assert result.accepted
        assert b"Passing outgoing" in result.return_msg


class TestRewardDisabled:
    """Rewards disabled by governance."""

    def test_zero_reward_rate_rejects(self, hook, rt):
        rt.state_db[b"RR"] = struct.pack("<q", 0)
        rt.state_db[b"RD"] = struct.pack("<q", DEFAULT_REWARD_DELAY)
        _setup_claimer_account(rt)
        result = rt.run(hook)
        assert result.rejected
        assert b"disabled" in result.return_msg

    def test_zero_reward_delay_rejects(self, hook, rt):
        rt.state_db[b"RR"] = struct.pack("<q", DEFAULT_REWARD_RATE)
        rt.state_db[b"RD"] = struct.pack("<q", 0)
        _setup_claimer_account(rt)
        result = rt.run(hook)
        assert result.rejected
        assert b"disabled" in result.return_msg


class TestRewardFirstClaim:
    """First time claim — no RewardAccumulator yet."""

    def test_first_claim_passes(self, hook, rt):
        """First claim (no sfRewardAccumulator) → setup txn, passes."""
        _setup_reward_state(rt)
        kl, data = account_root(CLAIMER_ADDR, Balance="100000000000")
        rt.ledger[kl] = data
        # Don't set slot_subfield for sfRewardAccumulator → DOESNT_EXIST
        result = rt.run(hook)
        assert result.accepted
        assert b"setup" in result.return_msg.lower()


class TestRewardClaim:
    """Actual reward claims with sufficient delay."""

    def test_successful_claim_emits(self, hook, rt):
        """Claim with sufficient delay → emits GenesisMint."""
        _setup_reward_state(rt)
        _setup_claimer_account(rt, balance_drops=100_000_000_000,
                               reward_time=0, reward_first=1,
                               reward_last=900, accumulator=50_000_000)
        result = rt.run(hook)
        assert result.accepted
        assert b"Emitted reward" in result.return_msg
        assert len(rt.emitted_txns) == 1

    def test_claim_too_soon_rejects(self, hook, rt):
        """Claim before delay period → rejected with wait message."""
        _setup_reward_state(rt)
        _setup_claimer_account(rt, reward_time=rt.ledger_last_time_val - 100)
        result = rt.run(hook)
        assert result.rejected
        assert b"must wait" in result.return_msg.lower()


class TestRewardNftoken:
    """nftoken.c — NFT import hook (XPOP-based, limited testability)."""

    def test_non_import_passes(self, nftoken_hook, rt):
        """Non-ttIMPORT transactions pass through."""
        rt.otxn_type = hookapi.ttPAYMENT
        result = rt.run(nftoken_hook)
        assert result.accepted
        assert b"Passing non ttIMPORT" in result.return_msg

    def test_outgoing_passes(self, nftoken_hook, rt):
        """Outgoing transactions pass."""
        rt.otxn_account = rt.hook_account
        result = rt.run(nftoken_hook)
        assert result.accepted
        assert b"Passing outgoing" in result.return_msg

    def test_import_without_xpop_rejects(self, nftoken_hook, rt):
        """ttIMPORT without XPOP data → rejected (xpop_slot returns DOESNT_EXIST)."""
        rt.otxn_type = 97  # ttIMPORT
        result = rt.run(nftoken_hook)
        assert result.rejected
        assert b"Failed to slot xpop" in result.return_msg
