"""Tests for top.c — the withdraw/deposit hook."""

import hashlib
import struct

import pytest

from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float
from hookz.handlers.emit import emit as _builtin_emit
from helpers import seed_xah_balance, balance_key_account, make_xah_amount
from hookz import hookapi
from hookz.xrpl.txn_parser import parse_object
from hookz.account import to_raddr


@pytest.fixture
def rt() -> HookRuntime:
    """Fresh runtime configured for an incoming Remit."""
    r = HookRuntime()
    r.hook_account = b"\x01" * 20
    r.otxn_account = b"\x02" * 20
    r.otxn_type = hookapi.ttREMIT

    # Slot overrides: no NFTs (default for all remits)
    r._slot_overrides[f"slot_subfield:1:{hookapi.sfURITokenIDs}"] = hookapi.DOESNT_EXIST
    r._slot_overrides[f"slot_subfield:1:{hookapi.sfMintURIToken}"] = hookapi.DOESNT_EXIST
    # Default: no sfAmounts (= withdrawal path). Tests override for deposit.
    r._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = hookapi.DOESNT_EXIST
    return r


@pytest.fixture
def hook(top_hook) -> Hook:
    return top_hook


def _setup_deposit(rt, snid=1, user_id=42, xah=True, amt_buf=None):
    """Configure rt for a deposit: sfAmounts present, slot mocking, DEPOSIT param."""
    rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = 2
    rt._slot_overrides["slot_count:2"] = 1
    rt._slot_overrides["slot_subarray:2:0"] = 3

    if amt_buf is None:
        if xah:
            amt_buf = make_xah_amount(100_000_000)  # 100 XAH
        else:
            amt_buf = bytearray(49)

    rt._slot_overrides["slot_data:3"] = bytes(amt_buf)

    # DEPOSIT param: snid(1) + 11 zeros + userid(8 LE) = 20 bytes
    deposit_param = bytearray(20)
    deposit_param[0] = snid
    struct.pack_into("<Q", deposit_param, 12, user_id)
    rt.params[b"DEPOSIT"] = bytes(deposit_param)


class TestPassthrough:
    def test_outgoing_passes(self, hook, rt):
        rt.otxn_account = rt.hook_account
        result = rt.run(hook)
        assert result.accepted
        assert b"outgoing" in result.return_msg.lower()

    def test_non_remit_passes(self, hook, rt):
        rt.otxn_type = hookapi.ttPAYMENT
        result = rt.run(hook)
        assert result.accepted
        assert b"non-remit" in result.return_msg.lower()


class TestValidation:
    def test_rejects_uri_token_ids(self, hook, rt):
        """Remit with URITokenIDs gets rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfURITokenIDs}"] = 2
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = hookapi.DOESNT_EXIST
        result = rt.run(hook)
        assert result.rejected
        assert b"URITokenIDs" in result.return_msg

    def test_rejects_mint_uri_token(self, hook, rt):
        """Remit with MintURIToken gets rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfURITokenIDs}"] = hookapi.DOESNT_EXIST
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfMintURIToken}"] = 2
        result = rt.run(hook)
        assert result.rejected
        assert b"MintURIToken" in result.return_msg

    def test_rejects_deposit_and_withdraw(self, hook, rt):
        """Remit with both DEPOSIT and WITHDRAW params is rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = 2
        rt._slot_overrides["slot_count:2"] = 1
        rt._slot_overrides["slot_subarray:2:0"] = 3
        rt._slot_overrides["slot_data:3"] = bytes(9)

        rt.params[b"DEPOSIT"] = bytes(20)
        rt.params[b"WITHDRAW"] = bytes(48)
        result = rt.run(hook)
        assert result.rejected
        assert b"both DEPOSIT and WITHDRAW" in result.return_msg


class TestDeposit:
    def test_xah_deposit_creates_balance(self, hook, rt):
        """XAH deposit credits user balance."""
        _setup_deposit(rt, snid=1, user_id=42, xah=True)
        result = rt.run(hook)
        assert result.accepted
        assert b"Credited" in result.return_msg

        # Verify the balance was written to state_db
        deposit_param = rt.params[b"DEPOSIT"]
        # Balance key is sha512h of the 60-byte key material
        key_material = bytearray(60)
        key_material[:20] = deposit_param[:20]
        h = hashlib.sha512(bytes(key_material)).digest()[:32]
        bal_key = b"B" + h[1:]
        assert bal_key in rt.state_db, "Balance entry should exist after deposit"
        bal_xfl = struct.unpack_from("<Q", rt.state_db[bal_key], 0)[0]
        assert xfl_to_float(bal_xfl) == pytest.approx(100.0, rel=1e-10)

        # Verify user info bitfield was created
        ui_key = b"U" + deposit_param
        assert ui_key in rt.state_db, "User info entry should exist after first deposit"
        ui_val = rt.state_db[ui_key]
        assert len(ui_val) == 32
        # Bit 0 should be set (first currency slot)
        assert ui_val[0] & 0x01, "First currency bit should be set in user info"

        # Verify traces: is_xah=1, size=9
        size_traces = [t for t in rt.traces if t.tag == "size"]
        assert any(t.value == 9 for t in size_traces), "Should trace size=9 for XAH"
        is_xah_traces = [t for t in rt.traces if t.tag == "is_xah"]
        assert any(t.value == 1 for t in is_xah_traces), "Should trace is_xah=1"

    def test_first_deposit_must_be_xah(self, hook, rt):
        """First deposit must be XAH (non-XAH rejected)."""
        # IOU amount: 49 bytes with non-zero currency
        amt_buf = bytearray(49)
        amt_buf[0] = 0xE0  # start marker
        # IOU amount header
        amt_buf[1] = 0xD4  # positive, exponent
        amt_buf[2] = 0x83  # mantissa high
        amt_buf[3] = 0x8D
        amt_buf[4] = 0x7E
        amt_buf[5] = 0xA4
        amt_buf[6] = 0xC6
        amt_buf[7] = 0x80
        amt_buf[8] = 0x00
        # Currency at bytes 9-28
        amt_buf[9] = 0x01  # non-zero currency = IOU
        # Issuer at bytes 29-48
        amt_buf[29] = 0x02

        _setup_deposit(rt, snid=1, user_id=42, xah=False, amt_buf=bytes(amt_buf))
        result = rt.run(hook)
        assert result.rejected
        assert b"First deposits must be in XAH" in result.return_msg

        # Verify trace showed is_xah=0
        is_xah_traces = [t for t in rt.traces if t.tag == "is_xah"]
        assert any(t.value == 0 for t in is_xah_traces), "Should trace is_xah=0 for IOU"
        # Size should be 49 for IOU
        size_traces = [t for t in rt.traces if t.tag == "size"]
        assert any(t.value == 49 for t in size_traces), "Should trace size=49 for IOU"

    def test_first_deposit_minimum_10_xah(self, hook, rt):
        """First deposit must be at least 10 XAH."""
        _setup_deposit(rt, snid=1, user_id=42, xah=True,
                       amt_buf=make_xah_amount(1_000_000))  # 1 XAH < 10 minimum
        result = rt.run(hook)
        assert result.rejected
        assert b"at least 10 XAH" in result.return_msg

        # No balance should have been created
        deposit_param = rt.params[b"DEPOSIT"]
        key_material = bytearray(60)
        key_material[:20] = deposit_param[:20]
        h = hashlib.sha512(bytes(key_material)).digest()[:32]
        bal_key = b"B" + h[1:]
        assert bal_key not in rt.state_db, "No balance should exist after rejected deposit"

    def test_deposit_rejects_invalid_snid_zero(self, hook, rt):
        """SNID 0 is rejected."""
        _setup_deposit(rt, snid=0, user_id=42, xah=True)
        result = rt.run(hook)
        assert result.rejected
        assert b"invalid SNID" in result.return_msg

    def test_deposit_rejects_invalid_snid_254(self, hook, rt):
        """SNID 254 is rejected (reserved for governance)."""
        _setup_deposit(rt, snid=254, user_id=42, xah=True)
        result = rt.run(hook)
        assert result.rejected
        assert b"invalid SNID" in result.return_msg

    def test_deposit_rejects_accid_target(self, hook, rt):
        """Depositing to an accid (non-zero middle bytes) is rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = 2
        rt._slot_overrides["slot_count:2"] = 1
        rt._slot_overrides["slot_subarray:2:0"] = 3
        rt._slot_overrides["slot_data:3"] = bytes(9)

        # DEPOSIT with non-zero bytes 2-12 (accid pattern)
        deposit_param = bytearray(20)
        deposit_param[0] = 1   # valid SNID
        deposit_param[1] = 0xAA  # non-zero = looks like accid
        rt.params[b"DEPOSIT"] = bytes(deposit_param)
        result = rt.run(hook)
        assert result.rejected
        assert b"social network tip account" in result.return_msg


class TestWithdrawal:
    def _make_withdraw(self, rt, account, xfl_amount, currency=None, issuer=None):
        """Set up WITHDRAW param and seed balance."""
        cur = currency or b"\x00" * 20
        iss = issuer or b"\x00" * 20
        withdraw_data = cur + iss + struct.pack("<Q", xfl_amount)
        rt.params[b"WITHDRAW"] = withdraw_data

        if currency and issuer:
            bal_key = balance_key_account(account, currency, issuer)
        else:
            bal_key = balance_key_account(account)
        return bal_key

    def test_xah_withdrawal_emits_remit(self, hook, rt):
        """Withdraw XAH → hook emits a Remit transaction."""
        xfl_100 = float_to_xfl(100.0)
        seed_xah_balance(rt, rt.otxn_account, xfl_100)
        xfl_50 = float_to_xfl(50.0)
        self._make_withdraw(rt, rt.otxn_account, xfl_50)

        result = rt.run(hook)
        assert result.accepted
        assert len(rt.emitted_txns) >= 1

        # Parse the emitted Remit
        txn = parse_object(rt.emitted_txns[0])
        assert txn["TransactionType"] == "Remit"
        assert "EmitDetails" in txn.fields
        assert txn["Account"] == to_raddr(rt.hook_account)
        assert txn["Destination"] == to_raddr(rt.otxn_account)

        # Verify Amounts field contains XAH amount for 50 drops worth
        amounts = txn.get("Amounts")
        assert amounts is not None, "Remit should have Amounts field"

        # Verify traces: drops, reqxfl, recalc should be present
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) == 1, "Should have exactly one drops trace"
        assert drops_traces[0].value == 50_000_000, "drops should be 50M (50 XAH)"
        reqxfl_traces = [t for t in rt.traces if t.tag == "reqxfl"]
        assert len(reqxfl_traces) == 1
        assert xfl_to_float(reqxfl_traces[0].raw) == pytest.approx(50.0, rel=1e-10)
        recalc_traces = [t for t in rt.traces if t.tag == "recalc"]
        assert len(recalc_traces) == 1

        # Remaining balance should be 50 XAH
        bal_key = balance_key_account(rt.otxn_account)
        remaining = struct.unpack_from("<Q", rt.state_db[bal_key], 0)[0]
        assert xfl_to_float(remaining) == pytest.approx(50.0, rel=1e-10)

    def test_full_withdrawal_clears_balance(self, hook, rt):
        """Withdrawing entire balance clears the state entry."""
        xfl_10 = float_to_xfl(10.0)
        seed_xah_balance(rt, rt.otxn_account, xfl_10)
        self._make_withdraw(rt, rt.otxn_account, xfl_10)

        result = rt.run(hook)
        assert result.accepted
        assert balance_key_account(rt.otxn_account) not in rt.state_db

        # Verify drops trace equals 10M (10 XAH in drops)
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) == 1
        assert drops_traces[0].value == 10_000_000

        # Verify emitted Remit
        txn = parse_object(rt.emitted_txns[0])
        assert txn["TransactionType"] == "Remit"
        assert txn["Account"] == to_raddr(rt.hook_account)
        assert txn["Destination"] == to_raddr(rt.otxn_account)

    def test_partial_withdrawal_leaves_remainder(self, hook, rt):
        """Withdrawing less than balance leaves the remainder."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        self._make_withdraw(rt, rt.otxn_account, float_to_xfl(30.0))

        result = rt.run(hook)
        assert result.accepted

        bal_key = balance_key_account(rt.otxn_account)
        remaining = struct.unpack_from("<Q", rt.state_db[bal_key], 0)[0]
        assert xfl_to_float(remaining) == pytest.approx(70.0, rel=1e-10)

        # drops should be 30M (30 XAH)
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) == 1
        assert drops_traces[0].value == 30_000_000

        # Emitted Remit should go to otxn_account
        txn = parse_object(rt.emitted_txns[0])
        assert txn["TransactionType"] == "Remit"
        assert txn["Destination"] == to_raddr(rt.otxn_account)

    def test_withdraw_more_than_balance_sends_all(self, hook, rt):
        """Requesting more than balance sends the whole balance."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(50.0))
        self._make_withdraw(rt, rt.otxn_account, float_to_xfl(999.0))

        result = rt.run(hook)
        assert result.accepted
        assert balance_key_account(rt.otxn_account) not in rt.state_db

        # reqxfl should be clamped to the actual balance (50 XAH), not 999
        reqxfl_traces = [t for t in rt.traces if t.tag == "reqxfl"]
        assert len(reqxfl_traces) == 1
        assert xfl_to_float(reqxfl_traces[0].raw) == pytest.approx(50.0, rel=1e-10)
        # drops should match 50 XAH = 50M drops
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) == 1
        assert drops_traces[0].value == 50_000_000

    def test_emit_call_captured(self, hook, rt):
        """The call log captures the emit host call."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(10.0))
        self._make_withdraw(rt, rt.otxn_account, float_to_xfl(10.0))

        result = rt.run(hook)
        assert result.accepted
        emit_calls = [c for c in result.call_log if c.name == "emit"]
        assert len(emit_calls) >= 1

    def test_no_balance_rejects(self, hook, rt):
        """Withdraw with no balance entry gets rejected."""
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))
        result = rt.run(hook)
        assert result.rejected
        assert b"No such user-currency-issuer" in result.return_msg
        # Should have a req trace but no drops/recalc (rejected before those)
        req_traces = [t for t in rt.traces if t.tag == "req"]
        assert len(req_traces) == 1
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) == 0, "No drops trace expected when balance missing"

    def test_missing_withdraw_param_rejects(self, hook, rt):
        """Withdrawal without WITHDRAW param gets rejected."""
        # No sfAmounts = withdrawal path, but no WITHDRAW param
        result = rt.run(hook)
        assert result.rejected
        assert b"WITHDRAW" in result.return_msg


class TestGovernanceEmit:
    """Withdrawal piggybacks governance SetHook emit."""

    def test_withdrawal_with_governance_emits_sethook(self, hook, rt):
        """Pending H entry causes SetHook emit alongside withdrawal."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        # Seed a governance entry: H + position → 64 bytes (hookhash + hookon)
        h_key = b"H" + bytes([0])
        h_val = b"\xAA" * 32 + b"\xBB" * 32
        rt.state_db[h_key] = h_val

        result = rt.run(hook)
        assert result.accepted
        assert b"+sethook" in result.return_msg.lower()

        # Should have emitted 2 txns: remit + sethook
        assert len(rt.emitted_txns) == 2

        # Parse the emitted Remit
        remit = parse_object(rt.emitted_txns[0])
        assert remit["TransactionType"] == "Remit"
        assert remit["Account"] == to_raddr(rt.hook_account)
        assert remit["Destination"] == to_raddr(rt.otxn_account)

        # Parse the emitted SetHook
        sethook = parse_object(rt.emitted_txns[1])
        assert sethook["TransactionType"] == "SetHook"
        assert sethook["Account"] == to_raddr(rt.hook_account)
        # SetHook should have Hooks array
        hooks = sethook.get("Hooks")
        assert hooks is not None, "SetHook should have Hooks array"
        assert len(hooks) == 1, "Position 0 should produce exactly 1 hook entry"
        real_hook = hooks[0].get("Hook", hooks[0])
        assert "HookHash" in real_hook, "Hook entry should have HookHash"
        assert "HookOn" in real_hook, "Hook entry should have HookOn"

        # Governance entry should be cleaned up
        assert h_key not in rt.state_db

        # Verify both emit_result traces show success (0)
        emit_traces = [t for t in rt.traces if t.tag == "emit_result"]
        assert len(emit_traces) == 2
        assert all(t.value == 0 for t in emit_traces)

    def test_withdrawal_without_governance_no_sethook(self, hook, rt):
        """No H entries → only remit emitted, no sethook."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        result = rt.run(hook)
        assert result.accepted
        assert b"Done." in result.return_msg
        assert b"+sethook" not in result.return_msg.lower()
        assert len(rt.emitted_txns) == 1

        # Only one emit_result trace (for the remit)
        emit_traces = [t for t in rt.traces if t.tag == "emit_result"]
        assert len(emit_traces) == 1
        assert emit_traces[0].value == 0

        # Verify drops trace
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) == 1
        assert drops_traces[0].value == 10_000_000

    def test_governance_at_position_3_emits_empty_hooks(self, hook, rt):
        """H entry at position 3 emits 3 empty hook objects before the real one."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        # Governance at position 3
        hook_hash = b"\xCC" * 32
        hook_on = b"\xDD" * 32
        h_key = b"H" + bytes([3])
        rt.state_db[h_key] = hook_hash + hook_on

        result = rt.run(hook)
        assert result.accepted
        assert b"+sethook" in result.return_msg.lower()
        assert len(rt.emitted_txns) == 2

        # Parse the SetHook — should have sfHooks array with position 3
        sethook = parse_object(rt.emitted_txns[1])
        assert sethook["TransactionType"] == "SetHook"
        assert sethook["Account"] == to_raddr(rt.hook_account)

        # sfHooks should be a list with 4 entries: 3 empty + 1 real
        hooks = sethook.get("Hooks")
        assert hooks is not None, f"No Hooks field in SetHook. Fields: {list(sethook.fields.keys())}"
        assert len(hooks) == 4, f"Expected 4 hook entries (3 empty + 1 real), got {len(hooks)}"

        # First 3 should be empty hook objects
        for i in range(3):
            assert hooks[i] == {} or hooks[i].get("Hook", {}) == {}, \
                f"Hook at position {i} should be empty, got {hooks[i]}"

        # Position 3 should have our hash and hookon
        real_hook = hooks[3].get("Hook", hooks[3])
        assert "HookHash" in real_hook, f"No HookHash in position 3: {real_hook}"
        assert "HookOn" in real_hook, f"No HookOn in position 3: {real_hook}"


class TestDepositEdgeCases:
    """Deposit validation edge cases."""

    def test_bad_slot_count_rejects(self, hook, rt):
        """sfAmounts with count != 1 gets rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = 2
        rt._slot_overrides["slot_count:2"] = 2  # wrong: must be 1
        rt._slot_overrides["slot_subarray:2:0"] = 3
        rt._slot_overrides["slot_data:3"] = bytes(9)
        rt.params[b"DEPOSIT"] = bytes(20)

        result = rt.run(hook)
        assert result.rejected
        assert b"one amount" in result.return_msg.lower()

    def test_invalid_amount_size_rejects(self, hook, rt):
        """Amount that's neither 9 nor 49 bytes gets rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = 2
        rt._slot_overrides["slot_count:2"] = 1
        rt._slot_overrides["slot_subarray:2:0"] = 3
        rt._slot_overrides["slot_data:3"] = bytes(20)  # wrong size

        deposit_param = bytearray(20)
        deposit_param[0] = 1
        struct.pack_into("<Q", deposit_param, 12, 42)
        rt.params[b"DEPOSIT"] = bytes(deposit_param)

        result = rt.run(hook)
        assert result.rejected
        assert b"Invalid amount" in result.return_msg

    def test_missing_deposit_param_rejects(self, hook, rt):
        """sfAmounts present but no DEPOSIT param → rejected."""
        rt._slot_overrides[f"slot_subfield:1:{hookapi.sfAmounts}"] = 2
        rt._slot_overrides["slot_count:2"] = 1
        rt._slot_overrides["slot_subarray:2:0"] = 3
        rt._slot_overrides["slot_data:3"] = make_xah_amount(100_000_000)

        result = rt.run(hook)
        assert result.rejected
        assert b"DEPOSIT" in result.return_msg


class TestIouWithdrawal:
    """IOU (non-XAH) withdrawal path."""

    def _seed_iou_balance(self, rt, currency, issuer, xfl_amount):
        bal_key = balance_key_account(rt.otxn_account, currency, issuer)
        rt.state_db[bal_key] = struct.pack("<Q", xfl_amount) + b"\x00"
        ui_key = b"U" + rt.otxn_account[:20]
        rt.state_db[ui_key] = bytes([0x01]) + b"\x00" * 31

    def _make_iou_withdraw(self, rt, currency, issuer, xfl_amount):
        rt.params[b"WITHDRAW"] = currency + issuer + struct.pack("<Q", xfl_amount)

    def test_iou_withdrawal_with_trustline(self, hook, rt):
        """IOU withdrawal succeeds when trustline exists."""
        currency = b"\x00" * 12 + b"USD" + b"\x00" * 5
        issuer = b"\xBB" * 20
        self._seed_iou_balance(rt, currency, issuer, float_to_xfl(100.0))
        self._make_iou_withdraw(rt, currency, issuer, float_to_xfl(50.0))

        # slot_set returns 3 → trustline exists
        rt._slot_overrides["slot_data:3"] = b"\x00" * 34

        result = rt.run(hook)
        assert result.accepted
        assert len(rt.emitted_txns) >= 1

        # Parse emitted Remit
        txn = parse_object(rt.emitted_txns[0])
        assert txn["TransactionType"] == "Remit"
        assert txn["Account"] == to_raddr(rt.hook_account)
        assert txn["Destination"] == to_raddr(rt.otxn_account)
        # Should have Amounts (IOU amount)
        amounts = txn.get("Amounts")
        assert amounts is not None, "IOU Remit should have Amounts field"

        # Remaining balance should be 50 XAH
        bal_key = balance_key_account(rt.otxn_account, currency, issuer)
        remaining = struct.unpack_from("<Q", rt.state_db[bal_key], 0)[0]
        assert xfl_to_float(remaining) == pytest.approx(50.0, rel=1e-10)

    def test_iou_withdrawal_no_trustline_rejects(self, hook, rt):
        """IOU withdrawal without trustline gets rejected."""
        currency = b"\x00" * 12 + b"USD" + b"\x00" * 5
        issuer = b"\xBB" * 20
        self._seed_iou_balance(rt, currency, issuer, float_to_xfl(100.0))
        self._make_iou_withdraw(rt, currency, issuer, float_to_xfl(50.0))

        # slot_set fails → no trustline
        rt.handlers["slot_set"] = lambda *a: -1

        result = rt.run(hook)
        assert result.rejected
        assert b"Trustline" in result.return_msg
        # No emitted txns when rejected
        assert len(rt.emitted_txns) == 0

    def test_iou_withdrawal_keylet_failure_rejects(self, hook, rt):
        """util_keylet returning error → rejected (line 417)."""
        currency = b"\x00" * 12 + b"USD" + b"\x00" * 5
        issuer = b"\xBB" * 20
        self._seed_iou_balance(rt, currency, issuer, float_to_xfl(100.0))
        self._make_iou_withdraw(rt, currency, issuer, float_to_xfl(50.0))

        rt.handlers["util_keylet"] = lambda *a: -1

        result = rt.run(hook)
        assert result.rejected
        assert b"Internal error generating keylet" in result.return_msg
        assert len(rt.emitted_txns) == 0


class TestDepositSanityChecks:
    """Deposit-path defensive checks that require mocking."""

    def test_float_sto_set_returns_zero_rejects(self, hook, rt):
        """amt <= 0 from float_sto_set → rejected (line 258)."""
        _setup_deposit(rt, snid=1, user_id=42, xah=True)
        # Mock float_sto_set to return 0
        rt.handlers["float_sto_set"] = lambda *a: 0

        result = rt.run(hook)
        assert result.rejected
        assert b"Invalid amount" in result.return_msg
        # amt trace should show the zero value
        amt_traces = [t for t in rt.traces if t.tag == "amt"]
        assert len(amt_traces) >= 1
        assert amt_traces[0].value == 0

    def test_insane_to_balance_sum_rejects(self, hook, rt):
        """float_sum producing insane to-balance → rejected (line 290)."""
        _setup_deposit(rt, snid=1, user_id=42, xah=True)
        # Mock float_sum to return 0 (fails the > to_bal check)
        rt.handlers["float_sum"] = lambda a, b: 0

        result = rt.run(hook)
        assert result.rejected
        assert b"Insane result" in result.return_msg

    def test_deposit_currency_slot_full_rejects(self, hook, rt):
        """User with all 256 currency slots full → rejected (line 306)."""
        _setup_deposit(rt, snid=1, user_id=42, xah=True)

        # Pre-seed user info with all 256 bits set
        deposit_param = rt.params[b"DEPOSIT"]
        ui_key = b"U" + deposit_param
        rt.state_db[ui_key] = b"\xFF" * 32  # all 256 slots taken

        result = rt.run(hook)
        assert result.rejected
        assert b"limit of 256" in result.return_msg


class TestWithdrawalSanityChecks:
    """Withdrawal-path defensive checks."""

    def test_negative_withdraw_amount_rejects(self, hook, rt):
        """reqxfl <= 0 → rejected (line 376)."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        # Encode 0 as the XFL amount (8 bytes LE)
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", 0)

        result = rt.run(hook)
        assert result.rejected
        assert b"negative withdraw" in result.return_msg.lower()

    def test_insane_from_balance_rejects(self, hook, rt):
        """Negative stored balance → rejected (line 379)."""
        # Seed a negative XFL balance (bit 62 clear = negative)
        neg_xfl = float_to_xfl(100.0) ^ (1 << 62)  # flip sign bit
        bal_key = balance_key_account(rt.otxn_account)
        rt.state_db[bal_key] = struct.pack("<Q", neg_xfl) + b"\x00"
        ui_key = b"U" + rt.otxn_account[:20]
        rt.state_db[ui_key] = bytes([0x01]) + b"\x00" * 31

        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        result = rt.run(hook)
        assert result.rejected
        assert b"negative from balance" in result.return_msg.lower()

    def test_insane_balance_subtraction_rejects(self, hook, rt):
        """float_sum producing insane subtraction result → rejected (line 403)."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        # Mock float_sum to return value >= from_bal (insane for subtraction)
        rt.handlers["float_sum"] = lambda a, b: float_to_xfl(999.0)

        result = rt.run(hook)
        assert result.rejected
        assert b"Insane final balance" in result.return_msg

    def test_insane_drops_computation_rejects(self, hook, rt):
        """Drops computation that's <= 0 or greater than reqxfl → rejected (line 443)."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        # Mock float_int to return 0 (insane drops)
        rt.handlers["float_int"] = lambda xfl, dec, abs_: 0

        result = rt.run(hook)
        assert result.rejected
        assert b"Insane drops" in result.return_msg
        # drops traces should all show the insane value (0)
        drops_traces = [t for t in rt.traces if t.tag == "drops"]
        assert len(drops_traces) >= 1
        assert all(t.value == 0 for t in drops_traces)

    def test_emit_remit_failure_rollback(self, hook, rt):
        """emit() returning negative → rollback (line 474)."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        rt.handlers["emit"] = lambda *a: -1

        result = rt.run(hook)
        assert result.rejected
        assert b"Emit remit failed" in result.return_msg
        # emit_result trace should show -1
        emit_traces = [t for t in rt.traces if t.tag == "emit_result"]
        assert len(emit_traces) == 1
        assert emit_traces[0].value == -1

    def test_emit_sethook_failure_rollback(self, hook, rt):
        """SetHook emit() failure → rollback (line 563)."""
        seed_xah_balance(rt, rt.otxn_account, float_to_xfl(100.0))
        rt.params[b"WITHDRAW"] = b"\x00" * 40 + struct.pack("<Q", float_to_xfl(10.0))

        # Seed governance entry
        rt.state_db[b"H" + bytes([0])] = b"\xAA" * 32 + b"\xBB" * 32

        # Let remit emit succeed, but sethook emit fail
        call_count = [0]

        def rigged_emit(*args):
            call_count[0] += 1
            if call_count[0] == 1:
                return _builtin_emit(rt, *args)  # remit succeeds
            return -1  # sethook fails

        rt.handlers["emit"] = rigged_emit

        result = rt.run(hook)
        assert result.rejected
        assert b"Emit sethook failed" in result.return_msg
        # Two emit_result traces: first success (0), second failure (-1)
        emit_traces = [t for t in rt.traces if t.tag == "emit_result"]
        assert len(emit_traces) == 2
        assert emit_traces[0].value == 0, "First emit (remit) should succeed"
        assert emit_traces[1].value == -1, "Second emit (sethook) should fail"
