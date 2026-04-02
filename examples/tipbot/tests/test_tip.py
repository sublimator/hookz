"""Tests for tip.c — the tipbot oracle hook."""

import struct

import pytest

from hookz.runtime import HookRuntime, Hook
from hookz.xfl import float_to_xfl, xfl_to_float
from hookz.handlers.float import float_sum as _builtin_float_sum
from hookz import hookapi
from helpers import (
    seed_members, seed_balance, make_opinion, balance_key, action_opinion,
    MEMBER_0, MEMBER_1, MEMBER_2,
)


@pytest.fixture
def rt() -> HookRuntime:
    r = HookRuntime()
    r.hook_account = b"\x01" * 20
    r.otxn_account = MEMBER_0
    r.otxn_type = hookapi.ttINVOKE
    return r


@pytest.fixture
def hook(tip_hook) -> Hook:
    return tip_hook




class TestPassthrough:
    def test_outgoing_passes(self, hook, rt):
        rt.otxn_account = rt.hook_account  # same = outgoing
        result = rt.run(hook)
        assert result.accepted
        assert b"outgoing" in result.return_msg.lower()
        assert result.return_code > 0  # __LINE__ from DONE macro
        # No emitted txns for passthrough
        assert len(rt.emitted_txns) == 0

    def test_non_invoke_passes(self, hook, rt):
        rt.otxn_type = hookapi.ttPAYMENT
        result = rt.run(hook)
        assert result.accepted
        assert b"non-invoke" in result.return_msg.lower()
        assert result.return_code > 0
        assert len(rt.emitted_txns) == 0


class TestBootstrap:
    def test_first_invoke_bootstraps_members(self, hook, rt):
        """With no members bitfield, hook bootstraps 3 initial members."""
        result = rt.run(hook)
        assert result.accepted
        assert result.return_code > 0

        # Find SM key by prefix
        sm_entries = {k: v for k, v in rt.state_db.items() if k[:2] == b"SM"}
        assert len(sm_entries) >= 1
        bitfield = list(sm_entries.values())[0]
        assert bitfield[0] == 0x07

        # Verify state_set calls were made (SM + M keys + P keys for 3 members)
        state_set_calls = [c for c in result.call_log if c.name == "state_set"]
        assert len(state_set_calls) >= 4  # SM bitfield + at least 3 member entries

        # Should have M entries for bootstrapped members
        m_entries = {k: v for k, v in rt.state_db.items() if k[:1] == b"M"}
        assert len(m_entries) >= 3

    def test_non_member_gets_cleanup_message(self, hook, rt):
        """After bootstrap, a non-member invoke still accepts (cleanup ran)."""
        sm_key = b"SM" + b"\x00" * 30
        rt.state_db[sm_key] = bytes([0x07]) + b"\x00" * 31

        result = rt.run(hook)
        assert result.accepted
        assert b"not a member" in result.return_msg.lower()
        assert result.return_code > 0
        # No emitted txns for non-member
        assert len(rt.emitted_txns) == 0


class TestMemberVote:
    def test_member_submits_vote(self, hook, rt):
        """A member can submit a vote and get 'S' result."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1)])
        rt.set_param(0, make_opinion())

        result = rt.run(hook)
        assert result.accepted
        assert b"Results:" in result.return_msg
        assert b"S" in result.return_msg
        assert result.return_code > 0

        # Vote should have created an opinion entry (O-prefixed key)
        o_entries = {k: v for k, v in rt.state_db.items() if k[:1] == b"O"}
        assert len(o_entries) >= 1

        # Should have state_set calls for the opinion + cleanup entry
        state_set_calls = [c for c in result.call_log if c.name == "state_set"]
        assert len(state_set_calls) >= 1

    def test_duplicate_vote_returns_V(self, hook, rt):
        """Same member voting on same post twice gets 'V'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        rt.set_param(0, make_opinion())

        r1 = rt.run(hook)
        assert r1.accepted
        assert b"S" in r1.return_msg

        # Capture opinion entry count after first vote
        o_entries_after_first = {k for k in rt.state_db if k[:1] == b"O"}

        # Same member, same opinion — should get V
        rt.set_param(0, make_opinion())
        r2 = rt.run(hook)
        assert r2.accepted
        assert b"V" in r2.return_msg
        assert r2.return_code > 0

        # No new opinion entries should be created for duplicate vote
        o_entries_after_second = {k for k in rt.state_db if k[:1] == b"O"}
        assert o_entries_after_second == o_entries_after_first

    def test_threshold_reached_actions_tip(self, hook, rt):
        """With 3 members, 2 votes (threshold) actions the tip → 'A'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        # Seed balance for from_user_id=99 so the tip can be actioned
        amt = float_to_xfl(1000.0)
        opinion = make_opinion(amount_xfl=amt)
        seed_balance(rt, user_id=99, amount_xfl=amt)

        # Member 0 votes → S
        rt.otxn_account = MEMBER_0
        rt.set_param(0, opinion)
        r1 = rt.run(hook)
        assert r1.accepted
        assert b"S" in r1.return_msg

        # Member 1 votes → A (threshold=2 for 3 members)
        rt.otxn_account = MEMBER_1
        rt.set_param(0, opinion)
        r2 = rt.run(hook)
        assert r2.accepted
        assert b"A" in r2.return_msg
        assert r2.return_code > 0

        # Verify traces were emitted during the actioning run
        assert len(rt.traces) > 0

        # Full drain: from_user_id=99 tipped entire balance, so entry is deleted
        from_key = balance_key(user_id=99)
        assert from_key not in rt.state_db

        # Verify to_user_id=42 got credited
        to_key = balance_key(user_id=42)
        to_val = rt.state_db.get(to_key)
        assert to_val is not None
        to_bal = struct.unpack_from("<Q", to_val, 0)[0]
        assert xfl_to_float(to_bal) == pytest.approx(1000.0, rel=1e-10)

    def test_already_actioned_returns_D(self, hook, rt):
        """After threshold, further votes on same post get 'D'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(1000.0)
        opinion = make_opinion(amount_xfl=amt)
        seed_balance(rt, user_id=99, amount_xfl=amt)

        # Two votes to action it
        rt.otxn_account = MEMBER_0
        rt.set_param(0, opinion)
        rt.run(hook)

        rt.otxn_account = MEMBER_1
        rt.set_param(0, opinion)
        rt.run(hook)

        # Capture state before third vote
        state_snapshot = dict(rt.state_db)

        # Third member → D
        rt.otxn_account = MEMBER_2
        rt.set_param(0, opinion)
        r3 = rt.run(hook)
        assert r3.accepted
        assert b"D" in r3.return_msg
        assert r3.return_code > 0

        # No balance changes should occur for already-actioned opinion
        from_key = balance_key(user_id=99)
        assert rt.state_db.get(from_key) == state_snapshot.get(from_key)

    def test_multiple_opinions_in_single_invoke(self, hook, rt):
        """Multiple param keys (0, 1) each get independent results."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])

        op_a = make_opinion(post_id=1001)
        op_b = make_opinion(post_id=2002)
        rt.set_param(0, op_a)
        rt.set_param(1, op_b)

        result = rt.run(hook)
        assert result.accepted
        assert result.return_code > 0
        # Both should be 'S' (submitted)
        msg = result.return_msg
        results_part = msg[msg.index(b"Results:") + 8:]
        assert results_part[1:3] == b"SS"

        # Two distinct opinion entries should exist (different post IDs)
        o_entries = {k: v for k, v in rt.state_db.items() if k[:1] == b"O"}
        assert len(o_entries) >= 2

        # Should have at least 2 state_set calls for opinion entries
        state_set_calls = [c for c in result.call_log if c.name == "state_set"]
        assert len(state_set_calls) >= 2


class TestBalance:
    """Balance and settlement tests — requires threshold to be met."""

    def test_tip_deducts_and_credits(self, hook, rt):
        """Actioned tip deducts from sender, credits to receiver."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        tip_amt = float_to_xfl(100.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(500.0))

        opinion = make_opinion(amount_xfl=tip_amt, from_user_id=99, to_user_id=42)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # Check from balance decreased
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(400.0, rel=1e-10)

        # Check to balance created
        to_key = balance_key(user_id=42)
        to_val = rt.state_db.get(to_key)
        assert to_val is not None
        to_bal = struct.unpack_from("<Q", to_val, 0)[0]
        assert xfl_to_float(to_bal) == pytest.approx(100.0, rel=1e-10)

        # Verify state_set calls include balance updates (at least 2: from + to)
        state_set_calls = [c for c in result.call_log if c.name == "state_set"]
        assert len(state_set_calls) >= 2

        # Verify traces were emitted for the action
        assert len(rt.traces) > 0

    def test_insufficient_balance_returns_B(self, hook, rt):
        """Tip larger than balance gets 'B'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(10.0))

        opinion = make_opinion(amount_xfl=float_to_xfl(100.0))
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"B" in result.return_msg
        assert result.return_code > 0

        # Balance should be unchanged (no deduction on insufficient funds)
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(10.0, rel=1e-10)

        # No credit to receiver
        to_key = balance_key(user_id=42)
        assert to_key not in rt.state_db

    def test_invalid_amount_returns_W(self, hook, rt):
        """Amount <= 0 gets 'W'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(100.0))

        # XFL 0 means amount is zero
        opinion = make_opinion(amount_xfl=0)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"W" in result.return_msg
        assert result.return_code > 0

        # Balance should be untouched
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(100.0, rel=1e-10)

    def test_full_drain_deletes_balance(self, hook, rt):
        """Tipping entire balance deletes the 'B' entry and clears user info bit."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(100.0)
        seed_balance(rt, user_id=99, amount_xfl=amt, bal_idx=3)

        opinion = make_opinion(amount_xfl=amt)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # Balance entry should be deleted
        from_key = balance_key(user_id=99)
        assert from_key not in rt.state_db

        # Receiver should have the full amount
        to_key = balance_key(user_id=42)
        to_val = rt.state_db.get(to_key)
        assert to_val is not None
        to_bal = struct.unpack_from("<Q", to_val, 0)[0]
        assert xfl_to_float(to_bal) == pytest.approx(100.0, rel=1e-10)


class TestMemberGovernance:
    """SNID 254 — member governance voting."""

    def _make_member_opinion(self, seat, account=None):
        """Build an 85-byte member governance opinion.

        Layout: SNID=254, byte[1]=seat (position), bytes[2:22]=account (20 bytes)
        Maps to: opinion[2]=seat, opinion[3:23]=account in C's 86-byte buffer
        """
        op = bytearray(85)
        op[0] = 254  # SNID for member governance
        op[1] = seat  # position byte (maps to opinion[2] in C)
        if account:
            op[2:22] = account[:20]  # accid (maps to opinion[3:23] in C)
        return bytes(op)

    def test_add_member(self, hook, rt):
        """SNID 254 with non-zero account adds member at seat."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        new_member = b"\x05" + b"\x00" * 19

        opinion = self._make_member_opinion(seat=3, account=new_member)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # Check new member is in state
        m_key = b"M" + new_member
        assert m_key in rt.state_db
        assert rt.state_db[m_key] == bytes([3])

        # Check bitfield has seat 3 set
        sm_key = b"SM" + b"\x00" * 30
        bf = rt.state_db[sm_key]
        assert (bf[0] >> 3) & 1 == 1

        # Original members' bits (0, 1, 2) should still be set
        assert bf[0] & 0x07 == 0x07

        # Verify state_set calls include M key and SM bitfield
        state_set_calls = [c for c in result.call_log if c.name == "state_set"]
        assert len(state_set_calls) >= 2

    def test_remove_member(self, hook, rt):
        """SNID 254 with zero account removes member at seat."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])

        # Remove member at seat 2 (zero account = remove)
        opinion = self._make_member_opinion(seat=2, account=None)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # Seat 2 bit should be cleared
        sm_key = b"SM" + b"\x00" * 30
        bf = rt.state_db[sm_key]
        assert (bf[0] >> 2) & 1 == 0

        # Seats 0 and 1 should still be set
        assert (bf[0] & 0x03) == 0x03

        # Bitfield value should be exactly 0x03 in first byte (seats 0+1)
        assert bf[0] == 0x03


class TestHookGovernance:
    """SNID 255 — hook governance voting."""

    def test_hook_governance_writes_H_entry(self, hook, rt):
        """SNID 255 stores hash+hookon at 'H'+position key."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])

        # Build hook governance opinion:
        # SNID=255, byte[1]=position, bytes[2:34]=hook hash (32), bytes[34:66]=hookon (32)
        op = bytearray(85)
        op[0] = 255
        op[1] = 0  # hook position 0
        op[2:34] = b"\xAA" * 32  # hook hash
        op[34:66] = b"\xBB" * 32  # hookon
        opinion = bytes(op)

        # Drive through threshold
        rt.otxn_account = MEMBER_0
        rt.set_param(0, opinion)
        rt.run(hook)
        rt.otxn_account = MEMBER_1
        rt.set_param(0, opinion)
        result = rt.run(hook)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # Check H entry written: key is 'H' + position, value is 64 bytes (hash + hookon)
        h_key = b"H" + bytes([0])
        assert h_key in rt.state_db
        h_val = rt.state_db[h_key]
        assert len(h_val) == 64
        assert h_val[:32] == b"\xAA" * 32
        assert h_val[32:] == b"\xBB" * 32

        # Verify state_set calls were made for the H entry
        state_set_calls = [c for c in result.call_log if c.name == "state_set"]
        assert len(state_set_calls) >= 1


class TestGC:
    """Amortized garbage collection of stale opinion entries."""

    def test_gc_deletes_stale_entries(self, hook, rt):
        """Entries older than current_ledger - 20 get reaped by the GC loop."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1)])
        rt.ledger_seq_val = 100

        # Create a fake opinion key (10 bytes like 'O' + snid + postid)
        opinion_key = b"O" + b"\x01" + struct.pack("<Q", 9999)

        # Set the opinion entry with old ledger_seq (50 < 100-20=80)
        opinion_val = bytearray(37)
        struct.pack_into("<I", opinion_val, 0, 50)  # ledger_seq = 50
        rt.state_db[opinion_key] = bytes(opinion_val)

        # Set cleanup boundaries: lower=0, upper=1 (one entry to clean)
        sh_key = b"SH" + b"\x00" * 30
        sl_key = b"SL" + b"\x00" * 30
        rt.state_db[sh_key] = struct.pack("<Q", 1)
        rt.state_db[sl_key] = struct.pack("<Q", 0)

        # Set cleanup entry: C + u64(0) → opinion_key
        c_key = b"C" + struct.pack("<Q", 0) + b"\x00" * 23
        rt.state_db[c_key] = opinion_key

        result = rt.run(hook)
        assert result.accepted
        assert result.return_code > 0

        # Opinion entry and cleanup entry should both be deleted
        assert opinion_key not in rt.state_db
        assert c_key not in rt.state_db

        # SL (lower bound) should have been advanced
        sl_val = rt.state_db.get(sl_key)
        assert sl_val is not None
        sl_new = struct.unpack_from("<Q", sl_val, 0)[0]
        assert sl_new >= 1  # lower bound advanced past the deleted entry

    def test_gc_preserves_fresh_entries(self, hook, rt):
        """Entries newer than cutoff are NOT reaped."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1)])
        rt.ledger_seq_val = 100

        opinion_key = b"O" + b"\x01" + struct.pack("<Q", 8888)

        # ledger_seq = 95 > cutoff (80), should survive
        opinion_val = bytearray(37)
        struct.pack_into("<I", opinion_val, 0, 95)
        rt.state_db[opinion_key] = bytes(opinion_val)

        sh_key = b"SH" + b"\x00" * 30
        sl_key = b"SL" + b"\x00" * 30
        rt.state_db[sh_key] = struct.pack("<Q", 1)
        rt.state_db[sl_key] = struct.pack("<Q", 0)

        c_key = b"C" + struct.pack("<Q", 0) + b"\x00" * 23
        rt.state_db[c_key] = opinion_key

        result = rt.run(hook)
        assert result.accepted
        assert result.return_code > 0

        # Both should still exist
        assert opinion_key in rt.state_db
        assert c_key in rt.state_db

        # SL should NOT have advanced (entry was fresh, GC skipped it)
        sl_val = rt.state_db.get(sl_key)
        assert sl_val is not None
        sl_new = struct.unpack_from("<Q", sl_val, 0)[0]
        assert sl_new == 0  # lower bound unchanged


class TestMemberReplace:
    """Member governance — replacing a member who already occupies a seat."""


    def test_replace_member_clears_old_seat(self, hook, rt):
        """Moving a member to a new seat clears the old seat's bit and P key."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])

        # Move MEMBER_2 (seat 2) to seat 3 via governance
        op = bytearray(85)
        op[0] = 254  # member governance
        op[1] = 3    # new seat
        op[2:22] = MEMBER_2[:20]
        opinion = bytes(op)

        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # Old seat 2 bit should be cleared
        sm_key = b"SM" + b"\x00" * 30
        bf = rt.state_db[sm_key]
        assert (bf[0] >> 2) & 1 == 0  # seat 2 cleared

        # New seat 3 bit should be set
        assert (bf[0] >> 3) & 1 == 1  # seat 3 set

        # Seats 0 and 1 should be unaffected
        assert bf[0] & 0x03 == 0x03

        # Exact bitfield: seats 0, 1, 3 set = 0b00001011 = 0x0B
        assert bf[0] == 0x0B

        # M key should point to seat 3
        m_key = b"M" + MEMBER_2[:20]
        assert rt.state_db[m_key] == bytes([3])


class TestTipToAccid:
    """Tip to r-address (IS_TOACC path)."""


    def test_tip_to_raccid_credits_under_accid(self, hook, rt):
        """When TO field has non-zero first 12 bytes, credits go to accid-based key."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(50.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(200.0))

        # to_acc: a 20-byte account ID (first 12 bytes non-zero → IS_TOACC)
        to_acc = b"\xAA" * 20
        opinion = make_opinion(amount_xfl=amt, to_acc=to_acc)

        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg
        assert result.return_code > 0

        # From balance should have decreased
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(150.0, rel=1e-10)

        # Verify traces were emitted during the action
        assert len(rt.traces) > 0


class TestGCEdgeCases:
    """GC edge cases — cleanup key missing, underflow fix."""

    def test_gc_breaks_on_missing_cleanup_key(self, hook, rt):
        """GC breaks when cleanup key doesn't exist in state (key_len < 0)."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1)])
        rt.ledger_seq_val = 100

        # Set bounds: lower=0, upper=5 — but no C entries exist
        sh_key = b"SH" + b"\x00" * 30
        sl_key = b"SL" + b"\x00" * 30
        rt.state_db[sh_key] = struct.pack("<Q", 5)
        rt.state_db[sl_key] = struct.pack("<Q", 0)

        # No C+0 key in state → state() returns DOESNT_EXIST → break
        result = rt.run(hook)
        assert result.accepted
        assert result.return_code > 0

        # SH and SL should still be present (GC didn't crash, just broke early)
        assert sh_key in rt.state_db
        assert sl_key in rt.state_db

    def test_gc_underflow_low_ledger(self, hook, rt):
        """When current_ledger < 20, cutoff is 0 — entries survive."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1)])
        rt.ledger_seq_val = 5  # < 20, so cutoff = 0

        opinion_key = b"O" + b"\x01" + struct.pack("<Q", 7777)
        opinion_val = bytearray(37)
        struct.pack_into("<I", opinion_val, 0, 1)  # ledger_seq = 1
        rt.state_db[opinion_key] = bytes(opinion_val)

        sh_key = b"SH" + b"\x00" * 30
        sl_key = b"SL" + b"\x00" * 30
        rt.state_db[sh_key] = struct.pack("<Q", 1)
        rt.state_db[sl_key] = struct.pack("<Q", 0)

        c_key = b"C" + struct.pack("<Q", 0) + b"\x00" * 23
        rt.state_db[c_key] = opinion_key

        result = rt.run(hook)
        assert result.accepted
        assert result.return_code > 0

        # Entry at ledger 1 should survive (1 > 0 = cutoff)
        assert opinion_key in rt.state_db
        assert c_key in rt.state_db

        # SL should not have advanced
        sl_val = rt.state_db.get(sl_key)
        assert sl_val is not None
        sl_new = struct.unpack_from("<Q", sl_val, 0)[0]
        assert sl_new == 0


class TestCurrencySlotOverflow:
    """User info bitfield — currency slot allocation across w[0]..w[3]."""


    def _user_info_key(self, snid=1, user_id=42):
        """Build the 21-byte user info key: 'U' + snid + 11_zeros + userid."""
        key = bytearray(21)
        key[0] = ord('U')
        key[1] = snid
        struct.pack_into("<Q", key, 13, user_id)
        return bytes(key)

    def test_currency_slot_in_second_word(self, hook, rt):
        """When first 64 bits of user_info are full, slot goes into w[1]."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(10.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(1000.0))

        # Pre-fill to_user's (userid=42) info bitfield: first 64 slots all taken
        to_info_key = self._user_info_key(snid=1, user_id=42)
        user_info = bytearray(32)
        struct.pack_into("<Q", user_info, 0, 0xFFFF_FFFF_FFFF_FFFF)  # w[0] all 1s
        rt.state_db[to_info_key] = bytes(user_info)

        opinion = make_opinion(amount_xfl=amt, to_user_id=42, from_user_id=99)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"A" in result.return_msg

        # Check that to_user_info now has bit 64 set (w[1] bit 0)
        updated_info = rt.state_db.get(to_info_key)
        assert updated_info is not None
        w1 = struct.unpack_from("<Q", updated_info, 8)[0]
        assert w1 & 1 == 1  # bit 64 = w[1] bit 0

        # w[0] should still be all 1s (unchanged)
        w0 = struct.unpack_from("<Q", updated_info, 0)[0]
        assert w0 == 0xFFFF_FFFF_FFFF_FFFF

        # Balance should have been credited
        to_key = balance_key(user_id=42)
        to_val = rt.state_db.get(to_key)
        assert to_val is not None
        to_bal = struct.unpack_from("<Q", to_val, 0)[0]
        assert xfl_to_float(to_bal) == pytest.approx(10.0, rel=1e-10)

    def test_currency_slot_full_returns_C(self, hook, rt):
        """User with all 256 currency slots full gets 'C'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(10.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(1000.0))

        # Fill ALL 256 bits of to_user's info
        to_info_key = self._user_info_key(snid=1, user_id=42)
        user_info = b"\xFF" * 32  # all 256 bits set
        rt.state_db[to_info_key] = user_info

        opinion = make_opinion(amount_xfl=amt, to_user_id=42, from_user_id=99)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"C" in result.return_msg
        assert result.return_code > 0

        # Balance should be unchanged (tip was not actioned)
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(1000.0, rel=1e-10)

        # User info should still be all 1s (unchanged)
        updated_info = rt.state_db.get(to_info_key)
        assert updated_info == b"\xFF" * 32


class TestPrematureActionBug:
    """Regression tests for the premature-actioning bug.

    The bug: post_info[4]=1 was written to state BEFORE validation checks
    (W/B/E/O/C). If validation fails, the post is permanently marked as
    actioned without the balance transfer. Future votes return 'D' and the
    tip can never be retried.
    """

    def test_insufficient_balance_not_permanently_actioned(self, hook, rt):
        """After 'B' (insufficient balance), a retry with funds should succeed."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(100.0)

        # Seed sender with insufficient balance
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(10.0))

        opinion = make_opinion(amount_xfl=amt, from_user_id=99, to_user_id=42)

        # First attempt: reaches threshold but fails validation (B)
        r1 = action_opinion(rt, hook, opinion)
        assert r1.accepted
        assert b"B" in r1.return_msg

        # Now fund the sender properly
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(500.0))

        # Second attempt: same opinion, new vote should NOT get 'D'
        # With the fix, post is not marked actioned, so a new vote works
        rt.otxn_account = MEMBER_2
        rt.set_param(0, opinion)
        r2 = rt.run(hook)
        assert r2.accepted
        # Should be 'A' (actioned) or 'S' (submitted), NOT 'D' (already done)
        assert b"D" not in r2.return_msg

    def test_zero_amount_not_permanently_actioned(self, hook, rt):
        """After 'W' (bad amount), post should not be stuck as actioned."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(100.0))

        # Zero amount opinion
        opinion = make_opinion(amount_xfl=0, from_user_id=99, to_user_id=42)

        # First attempt: W (bad amount)
        r1 = action_opinion(rt, hook, opinion)
        assert r1.accepted
        assert b"W" in r1.return_msg

        # The opinion should NOT be marked as actioned in state
        opinion_key = opinion[:10]
        post_val = rt.state_db.get(opinion_key)
        if post_val is not None and len(post_val) >= 5:
            assert post_val[4] == 0, "post_info[4] should be 0 (not actioned) after failed validation"

    def test_currency_overflow_not_permanently_actioned(self, hook, rt):
        """After 'C' (currency slots full), post should not be stuck."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(10.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(1000.0))

        # Fill all 256 currency slots for receiver
        to_info_key = b"U" + bytes([1]) + b"\x00" * 11 + struct.pack("<Q", 42)
        rt.state_db[to_info_key] = b"\xFF" * 32

        opinion = make_opinion(amount_xfl=amt, to_user_id=42, from_user_id=99)

        # First attempt: C (currency slots full)
        r1 = action_opinion(rt, hook, opinion)
        assert r1.accepted
        assert b"C" in r1.return_msg

        # The opinion should NOT be marked as actioned
        opinion_key = opinion[:10]
        post_val = rt.state_db.get(opinion_key)
        if post_val is not None and len(post_val) >= 5:
            assert post_val[4] == 0, "post_info[4] should be 0 after 'C' failure"


class TestFloatSanityChecks:
    """Defensive checks in tip.c for pathological float_sum results."""


    def test_from_balance_sanity_check_E(self, hook, rt):
        """If float_sum(from_bal, -amt) returns negative → 'E'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(10.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(100.0))

        # Mock float_sum to return -1 (negative XFL) for the from_bal subtraction
        call_count = [0]

        def rigged_float_sum(a, b):
            call_count[0] += 1
            if call_count[0] == 1:
                return -1  # negative = error
            return _builtin_float_sum(rt, a, b)

        rt.handlers["float_sum"] = rigged_float_sum

        opinion = make_opinion(amount_xfl=amt)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"E" in result.return_msg
        assert result.return_code > 0

        # Balance should be unchanged (sanity check prevented deduction)
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(100.0, rel=1e-10)

    def test_to_balance_overflow_O(self, hook, rt):
        """If float_sum(to_bal, amt) returns ≤ 0 or less than original → 'O'."""
        seed_members(rt, [(MEMBER_0, 0), (MEMBER_1, 1), (MEMBER_2, 2)])
        amt = float_to_xfl(10.0)
        seed_balance(rt, user_id=99, amount_xfl=float_to_xfl(100.0))

        call_count = [0]

        def rigged_float_sum(a, b):
            call_count[0] += 1
            if call_count[0] == 1:
                return _builtin_float_sum(rt, a, b)
            return 0

        rt.handlers["float_sum"] = rigged_float_sum

        opinion = make_opinion(amount_xfl=amt)
        result = action_opinion(rt, hook, opinion)
        assert result.accepted
        assert b"O" in result.return_msg
        assert result.return_code > 0

        # Balance should be unchanged (overflow prevented the tip)
        from_key = balance_key(user_id=99)
        from_val = rt.state_db.get(from_key)
        assert from_val is not None
        from_bal = struct.unpack_from("<Q", from_val, 0)[0]
        assert xfl_to_float(from_bal) == pytest.approx(100.0, rel=1e-10)
