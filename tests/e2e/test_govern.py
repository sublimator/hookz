"""E2E tests for Xahau governance hook (govern.c).

Tests the governance initialization flow and voting mechanics.
"""

import struct

import pytest

from hookz import hookapi
from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl

# Genesis account (hardcoded in govern.c)
GENESIS = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
GENESIS_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")

MEMBER_0 = bytes.fromhex("01" * 20)
MEMBER_1 = bytes.fromhex("02" * 20)
MEMBER_2 = bytes.fromhex("03" * 20)
NON_MEMBER = bytes.fromhex("FF" * 20)


@pytest.fixture
def hook(govern_hook):
    return govern_hook


@pytest.fixture
def rt():
    """Runtime configured as L1 governance (hook on genesis account)."""
    r = HookRuntime()
    r.hook_account = GENESIS_ACCID
    r.otxn_account = GENESIS_ACCID
    r.otxn_type = hookapi.ttINVOKE
    return r


def _le_xfl(value: float) -> bytes:
    """Pack an XFL as little-endian 8 bytes (how govern.c reads them)."""
    return struct.pack("<q", float_to_xfl(value))


# ---------------------------------------------------------------------------
# Initialization (first invoke — no MC state key yet)
# ---------------------------------------------------------------------------

class TestGovernInit:
    """First invocation sets up the governance table."""

    def test_init_with_3_members(self, hook, rt):
        """Initialize with 3 members, reward rate and delay."""
        rt.params[b"IMC"] = bytes([3])
        rt.params[b"IS\x00"] = MEMBER_0
        rt.params[b"IS\x01"] = MEMBER_1
        rt.params[b"IS\x02"] = MEMBER_2
        rt.params[b"IRR"] = _le_xfl(0.001)  # 0.1% reward rate
        rt.params[b"IRD"] = _le_xfl(86400.0)  # 1 day delay

        result = rt.run(hook)
        assert result.accepted
        assert b"Setup completed" in result.return_msg

        # Check member count state
        assert rt.state_db[b"MC"] == bytes([3])

        # Check reward rate and delay
        assert rt.state_db[b"RR"] == _le_xfl(0.001)
        assert rt.state_db[b"RD"] == _le_xfl(86400.0)

        # Check member seats (reverse key: seat_id → account)
        assert rt.state_db[bytes([0])] == MEMBER_0
        assert rt.state_db[bytes([1])] == MEMBER_1
        assert rt.state_db[bytes([2])] == MEMBER_2

        # Check member lookup (forward key: account → seat_id)
        assert rt.state_db[MEMBER_0] == bytes([0])
        assert rt.state_db[MEMBER_1] == bytes([1])
        assert rt.state_db[MEMBER_2] == bytes([2])

    def test_init_with_1_member(self, hook, rt):
        """Minimum: 1 member."""
        rt.params[b"IMC"] = bytes([1])
        rt.params[b"IS\x00"] = MEMBER_0
        rt.params[b"IRR"] = _le_xfl(0.01)
        rt.params[b"IRD"] = _le_xfl(3600.0)

        result = rt.run(hook)
        assert result.accepted
        assert rt.state_db[b"MC"] == bytes([1])

    def test_init_zero_members_rejected(self, hook, rt):
        """IMC=0 should be rejected."""
        rt.params[b"IMC"] = bytes([0])
        rt.params[b"IRR"] = _le_xfl(0.01)
        rt.params[b"IRD"] = _le_xfl(3600.0)

        result = rt.run(hook)
        assert result.rejected
        assert b"must be > 0" in result.return_msg

    def test_init_too_many_members_rejected(self, hook, rt):
        """IMC > 20 (SEAT_COUNT) should be rejected."""
        rt.params[b"IMC"] = bytes([21])
        rt.params[b"IRR"] = _le_xfl(0.01)
        rt.params[b"IRD"] = _le_xfl(3600.0)

        result = rt.run(hook)
        assert result.rejected
        assert b"<= Seat Count" in result.return_msg

    def test_init_missing_imc_rejected(self, hook, rt):
        """Missing IMC parameter."""
        result = rt.run(hook)
        assert result.rejected
        assert b"IMC" in result.return_msg

    def test_init_missing_reward_rate_rejected(self, hook, rt):
        """L1 table requires IRR."""
        rt.params[b"IMC"] = bytes([1])
        rt.params[b"IS\x00"] = MEMBER_0
        rt.params[b"IRD"] = _le_xfl(3600.0)
        # No IRR

        result = rt.run(hook)
        assert result.rejected
        assert b"IRR" in result.return_msg

    def test_init_missing_reward_delay_rejected(self, hook, rt):
        """L1 table requires IRD."""
        rt.params[b"IMC"] = bytes([1])
        rt.params[b"IS\x00"] = MEMBER_0
        rt.params[b"IRR"] = _le_xfl(0.01)
        # No IRD

        result = rt.run(hook)
        assert result.rejected
        assert b"IRD" in result.return_msg

    def test_init_zero_reward_delay_rejected(self, hook, rt):
        """IRD=0 should be rejected."""
        rt.params[b"IMC"] = bytes([1])
        rt.params[b"IS\x00"] = MEMBER_0
        rt.params[b"IRR"] = _le_xfl(0.01)
        rt.params[b"IRD"] = struct.pack("<q", 0)

        result = rt.run(hook)
        assert result.rejected
        assert b"Reward Delay must be > 0" in result.return_msg


# ---------------------------------------------------------------------------
# Non-invoke transactions
# ---------------------------------------------------------------------------

class TestGovernNonInvoke:
    """Non-invoke transactions should pass through."""

    def test_payment_passes(self, hook, rt):
        rt.otxn_type = hookapi.ttPAYMENT
        result = rt.run(hook)
        assert result.accepted
        assert b"Passing non-Invoke" in result.return_msg


# ---------------------------------------------------------------------------
# Voting (after initialization)
# ---------------------------------------------------------------------------

def _setup_initialized_rt(rt, member_count=3):
    """Set up state as if initialization already happened."""
    rt.state_db[b"MC"] = bytes([member_count])
    rt.state_db[b"RR"] = _le_xfl(0.001)
    rt.state_db[b"RD"] = _le_xfl(86400.0)
    for i in range(member_count):
        member = bytes([i + 1] * 20)
        rt.state_db[bytes([i])] = member
        rt.state_db[member] = bytes([i])


class TestGovernVoting:
    """Voting on topics after initialization."""

    def test_non_member_rejected(self, hook, rt):
        """Non-member trying to vote → rejected."""
        _setup_initialized_rt(rt)
        rt.otxn_account = NON_MEMBER
        rt.params[b"T"] = b"S\x00"  # topic: seat 0
        rt.params[b"V"] = MEMBER_0  # vote data

        result = rt.run(hook)
        assert result.rejected
        assert b"not currently a governance member" in result.return_msg

    def test_member_votes_on_seat(self, hook, rt):
        """Member votes on a seat topic."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0
        rt.params[b"T"] = b"S\x03"  # topic: seat 3 (empty)
        rt.params[b"V"] = bytes([0xAA] * 20)  # new member for seat 3

        result = rt.run(hook)
        assert result.accepted
        assert b"Not yet enough votes" in result.return_msg

    def test_missing_topic_rejected(self, hook, rt):
        """Missing T parameter."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0

        result = rt.run(hook)
        assert result.rejected
        assert b"TOPIC must be specified" in result.return_msg

    def test_invalid_topic_type_rejected(self, hook, rt):
        """Invalid topic type (not S/H/R)."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0
        rt.params[b"T"] = b"X\x00"

        result = rt.run(hook)
        assert result.rejected
        assert b"TOPIC" in result.return_msg

    def test_seat_topic_out_of_range(self, hook, rt):
        """Seat topic > 19."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0
        rt.params[b"T"] = b"S\x14"  # seat 20
        rt.params[b"V"] = bytes([0xAA] * 20)

        result = rt.run(hook)
        assert result.rejected
        assert b"0 through 19" in result.return_msg

    def test_hook_topic_out_of_range(self, hook, rt):
        """Hook topic > 10."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0
        rt.params[b"T"] = b"H\x0B"  # hook 11
        rt.params[b"V"] = bytes([0xAA] * 32)

        result = rt.run(hook)
        assert result.rejected
        assert b"0 through 9" in result.return_msg

    def test_reward_topic_invalid_subtype(self, hook, rt):
        """Reward topic must be R or D."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0
        rt.params[b"T"] = b"RX"
        rt.params[b"V"] = _le_xfl(0.01)

        result = rt.run(hook)
        assert result.rejected
        assert b"rate" in result.return_msg.lower() or b"delay" in result.return_msg.lower()

    def test_missing_vote_data_rejected(self, hook, rt):
        """Missing V parameter."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0
        rt.params[b"T"] = b"S\x00"
        # No V parameter

        result = rt.run(hook)
        assert result.rejected
        assert b"VOTE data" in result.return_msg

    def test_duplicate_vote_passes(self, hook, rt):
        """Voting the same way twice → accept (already cast)."""
        _setup_initialized_rt(rt)
        rt.otxn_account = MEMBER_0

        vote_data = bytes([0xAA] * 20)
        # Pre-seed the vote state as if member already voted this way
        vote_key = bytearray(32)
        vote_key[0] = ord('V')
        vote_key[1] = ord('S')
        vote_key[2] = 3  # seat 3
        vote_key[3] = 1  # layer 1
        vote_key[12:32] = MEMBER_0
        rt.state_db[bytes(vote_key)] = vote_data

        rt.params[b"T"] = b"S\x03"
        rt.params[b"V"] = vote_data

        result = rt.run(hook)
        assert result.accepted
        assert b"already cast" in result.return_msg


class TestGovernRewardVoting:
    """Voting on reward rate/delay topics."""

    def test_unanimous_reward_rate_change(self, hook, rt):
        """All 3 members vote for same RR → actioned (100% threshold)."""
        _setup_initialized_rt(rt, member_count=3)
        new_rate = _le_xfl(0.005)

        # Pre-seed 2 existing votes
        for i in range(2):
            member = bytes([i + 1] * 20)
            vote_key = bytearray(32)
            vote_key[0] = ord('V')
            vote_key[1] = ord('R')
            vote_key[2] = ord('R')
            vote_key[3] = 1
            vote_key[12:32] = member
            rt.state_db[bytes(vote_key)] = new_rate

        # Pre-seed vote counter at 2
        count_key = bytearray(32)
        count_key[0] = ord('C')
        count_key[1] = ord('R')
        count_key[2] = ord('R')
        count_key[3] = 1
        count_key[24:32] = new_rate
        rt.state_db[bytes(count_key)] = bytes([2])

        # Third member casts the deciding vote
        rt.otxn_account = MEMBER_2
        rt.params[b"T"] = b"RR"
        rt.params[b"V"] = new_rate

        result = rt.run(hook)
        assert result.accepted
        assert b"Reward rate change actioned" in result.return_msg

        # RR state should be updated
        assert rt.state_db[b"RR"] == new_rate
