"""featureRNG — dice and util_random.

Behaviour ported from xahaud:src/test/app/RNG_test.cpp:746 (`testHooks`) and
:727 (`testNoEntropy`), restricted to what one emulated execution can show:
the ledger-building half of that suite (ttENTROPY, UNLReport, commitments)
has no counterpart here, because a test states the round's result directly.

There are no upstream known-answer outputs — on chain the state comes from
validator reveals. So the known-answer tests below pin hookz's byte layout
instead, and every expected value is computed *here*, from a byte
concatenation spelled out in the test with hashlib, never by calling
`hookz.handlers.rng`. Read `_preimage` against
xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1976 to audit the layout without
trusting the implementation.
"""

from __future__ import annotations

import hashlib

import pytest
import wasmtime

from hookz import hookapi
from hookz.handlers import rng
from hookz.handlers.rng import dice, util_random
from hookz.runtime import HookRuntime, RandomState

# ---------------------------------------------------------------------------
# The spelled-out layout
# ---------------------------------------------------------------------------

STATE = bytes(range(0x00, 0x20))
TXID = bytes(range(0x20, 0x40))
ACCOUNT = bytes(range(0x40, 0x54))
HOOK_HASH = bytes(range(0x60, 0x80))
CHAIN_POSITION = 3

U64_MAX = 2**64 - 1


def H(data: bytes) -> bytes:
    """sha512Half."""
    return hashlib.sha512(data).digest()[:32]


def step(state: bytes) -> bytes:
    """sha512Half(uint32_t 0x524E4749, state) — the tag big-endian is 'RNGI'."""
    return H(b"RNGI" + state)


def _preimage(state: bytes, *, txid: bytes = TXID, account: bytes = ACCOUNT,
              hook_hash: bytes = HOOK_HASH, position: int = CHAIN_POSITION,
              strong: int = 1, callback: int = 0, wasm_param: int = 0) -> bytes:
    """The 127 bytes rng_next hashes, one field per line."""
    pre = (
        b"RNGO"                             # uint32_t 0x524E474F, big-endian
        + state                             # uint256, raw
        + txid                              # uint256, raw
        + account                           # AccountID, raw
        + hook_hash                         # uint256, raw
        + bytes([position])                 # uint8_t hookChainPosition
        + bytes([strong])                   # uint8_t isStrong
        + bytes([callback])                 # uint8_t isCallback
        + wasm_param.to_bytes(4, "big")     # uint32_t wasmParam, big-endian
    )
    assert len(pre) == 4 + 32 + 32 + 20 + 32 + 1 + 1 + 1 + 4 == 127
    return pre


def out(state: bytes = STATE, **inputs) -> bytes:
    return H(_preimage(state, **inputs))


@pytest.fixture
def rt() -> HookRuntime:
    """A runtime with memory and every draw input pinned to the constants."""
    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    r._store = store
    r._memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r.amendments.add("featureRNG")
    r.seed_random(STATE)
    r.otxn_id_val = TXID
    r.hook_account = ACCOUNT
    r.hook_hash = HOOK_HASH
    r.hook_chain_position = CHAIN_POSITION
    return r


def _consumed_nothing(rt: HookRuntime) -> bool:
    return rt.random.random_data == STATE and rt._rng_draws == 0


# ---------------------------------------------------------------------------
# Known answers
# ---------------------------------------------------------------------------

class TestKnownAnswers:
    def test_the_block_is_the_hash_of_the_spelled_out_preimage(self, rt):
        """util_random(32) writes the drawn block itself."""
        assert util_random(rt, 0, 32) == 32
        assert rt._read_memory(0, 32) == out()

    def test_the_layout_is_pinned_as_bytes_too(self, rt):
        """The same value as a literal, so a change to `_preimage` above that
        also changed the implementation cannot pass unnoticed."""
        util_random(rt, 0, 32)
        assert rt._read_memory(0, 32).hex().upper() == (
            "0806A53816BA260DF1BCDEB221904E742D1BC7694E226EBFF89FFBBC8D9ACE69")

    def test_each_draw_steps_the_state_once(self, rt):
        """xahaud:src/test/app/RNG_test.cpp:820 — s2 == step(step(s1)) across
        two draws."""
        util_random(rt, 0, 32)
        assert rt.random.random_data == step(STATE)
        assert step(STATE).hex().upper() == (
            "4081857D888CC1638F40E6CDE4E10C9C75062FF69F84F1D1CAB4066F9F5E4E9F")
        util_random(rt, 0, 32)
        assert rt.random.random_data == step(step(STATE))

    def test_the_second_draw_hashes_the_stepped_state(self, rt):
        util_random(rt, 0, 32)
        util_random(rt, 32, 32)
        first, second = rt._read_memory(0, 32), rt._read_memory(32, 32)
        assert first != second
        assert second == out(step(STATE))
        assert second.hex().upper() == (
            "6C829D92E2D3AEE8195226D3175CDBA412612AE281F8D9C814032A7C2990A247")

    def test_util_random_extends_by_rehashing_and_truncates(self, rt):
        b0 = out()
        b1 = H(b0)
        b2 = H(b1)
        b3 = H(b2)
        assert util_random(rt, 0, 100) == 100
        assert rt._read_memory(0, 100) == b0 + b1 + b2 + b3[:4]

    def test_util_random_short(self, rt):
        assert util_random(rt, 0, 5) == 5
        assert rt._read_memory(0, 5) == out()[:5]

    def test_util_random_512_is_sixteen_blocks(self, rt):
        expected, block = b"", out()
        for _ in range(16):
            expected += block
            block = H(block)
        assert util_random(rt, 0, 512) == 512
        assert rt._read_memory(0, 512) == expected

    def test_dice_reduces_the_first_big_endian_word(self, rt):
        word0 = int.from_bytes(out()[0:8], "big")
        excess = 2**64 % 6
        assert excess == 4
        assert word0 <= U64_MAX - excess, "this block's first word is accepted"
        assert dice(rt, 6) == word0 % 6 == 5

    def test_the_draw_is_recorded_as_evidence(self, rt):
        util_random(rt, 0, 32)
        (draw,) = rt._random_draws
        assert (draw.api, draw.state, draw.output) == ("util_random", STATE, out())


class TestEveryInputReachesTheHash:
    """Each field changes the block exactly as `_preimage` says it does."""

    def test_chain_position(self, rt):
        rt.hook_chain_position = 9
        util_random(rt, 0, 32)
        assert rt._read_memory(0, 32) == out(position=9)

    def test_hook_account(self, rt):
        rt.hook_account = b"\x07" * 20
        util_random(rt, 0, 32)
        assert rt._read_memory(0, 32) == out(account=b"\x07" * 20)

    def test_applied_txn_id_overrides_otxn_id(self, rt):
        rt.applied_txn_id = b"\x55" * 32
        util_random(rt, 0, 32)
        assert rt._read_memory(0, 32) == out(txid=b"\x55" * 32)

    def test_without_either_the_txid_is_what_otxn_id_serves(self, rt):
        from hookz.handlers.otxn import otxn_id

        rt.otxn_id_val = None
        otxn_id(rt, 64, 32, 0)
        served = rt._read_memory(64, 32)
        util_random(rt, 0, 32)
        assert rt._read_memory(0, 32) == out(txid=served)

    def test_weak_again_as_weak_and_callbacks(self, rt):
        """wasmParam is the export's argument; strong only for hook(0)."""
        cases = [("hook", 1, 0, 0), ("hook", 2, 0, 0),
                 ("cbak", 0, 0, 1), ("cbak", 1, 0, 1)]
        for export, arg, strong, callback in cases:
            rt._current_export, rt._current_arg = export, arg
            rt.seed_random(STATE)
            util_random(rt, 0, 32)
            assert rt._read_memory(0, 32) == out(
                strong=strong, callback=callback, wasm_param=arg), (export, arg)


# ---------------------------------------------------------------------------
# Refusals, in the host's order — none consumes a draw
# ---------------------------------------------------------------------------

class TestTheDrawIsRefused:
    def test_no_random_object(self, rt):
        """xahaud:src/test/app/RNG_test.cpp:727 — no entropy round has run."""
        rt.random = None
        assert dice(rt, 6) == hookapi.TOO_LITTLE_ENTROPY
        assert util_random(rt, 0, 32) == hookapi.TOO_LITTLE_ENTROPY
        assert rt._rng_draws == 0

    def test_a_fresh_runtime_has_no_random_object(self):
        assert HookRuntime().random is None

    def test_amendment_off(self, rt):
        rt.amendments.discard("featureRNG")
        assert dice(rt, 6) == hookapi.TOO_LITTLE_ENTROPY
        assert util_random(rt, 0, 32) == hookapi.TOO_LITTLE_ENTROPY
        assert _consumed_nothing(rt)

    def test_amendment_off_wins_over_the_draw_limit(self, rt):
        rt._rng_draws = rng.MAX_RNG_DRAWS
        rt.amendments.discard("featureRNG")
        assert dice(rt, 6) == hookapi.TOO_LITTLE_ENTROPY

    @pytest.mark.parametrize("seeded_for", [99, 101, 0])
    def test_seeded_for_another_ledger(self, rt, seeded_for):
        """Including the previous ledger: the open-ledger preview exception
        (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1959) is not modelled."""
        rt.random.ledger_seq = seeded_for
        assert dice(rt, 6) == hookapi.TOO_LITTLE_ENTROPY
        assert _consumed_nothing(rt)

    def test_seeding_pins_the_current_ledger(self, rt):
        assert rt.random.ledger_seq == rt.ledger_seq_val
        rt.ledger_seq_val += 1
        assert dice(rt, 6) == hookapi.TOO_LITTLE_ENTROPY

    @pytest.mark.parametrize("count,denominator", [
        (0, 0), (0, 1), (3, 5), (7, 9), (79, 100)])
    def test_too_few_contributed(self, rt, count, denominator):
        rt.random.entropy_count = count
        rt.random.entropy_denominator = denominator
        assert dice(rt, 6) == hookapi.TOO_LITTLE_ENTROPY
        assert _consumed_nothing(rt)

    @pytest.mark.parametrize("count,denominator", [
        (1, 0), (4, 5), (80, 100), (0xFFFF, 0xFFFF), (1, 1)])
    def test_eighty_percent_is_enough(self, rt, count, denominator):
        rt.random.entropy_count = count
        rt.random.entropy_denominator = denominator
        assert 0 <= dice(rt, 6) < 6

    def test_dice_zero_is_refused_before_drawing(self, rt):
        assert dice(rt, 0) == hookapi.INVALID_ARGUMENT
        assert _consumed_nothing(rt)

    def test_dice_zero_even_without_entropy(self, rt):
        rt.random = None
        assert dice(rt, 0) == hookapi.INVALID_ARGUMENT

    def test_util_random_zero_and_oversized(self, rt):
        assert util_random(rt, 0, 0) == hookapi.TOO_SMALL
        assert util_random(rt, 0, 513) == hookapi.TOO_BIG
        assert _consumed_nothing(rt)

    def test_util_random_bounds_come_first(self, rt):
        mem = rt._memory.data_len(rt._store)
        assert util_random(rt, mem, 0) == hookapi.OUT_OF_BOUNDS
        assert util_random(rt, mem - 10, 513) == hookapi.OUT_OF_BOUNDS
        assert util_random(rt, mem - 10, 11) == hookapi.OUT_OF_BOUNDS
        assert _consumed_nothing(rt)
        assert util_random(rt, mem - 10, 10) == 10


class TestTheDrawLimit:
    def test_256_draws_then_too_many_nonces(self, rt):
        for _ in range(256):
            assert 0 <= dice(rt, 6) < 6
        assert dice(rt, 6) == hookapi.TOO_MANY_NONCES
        assert util_random(rt, 0, 32) == hookapi.TOO_MANY_NONCES
        expected = STATE
        for _ in range(256):
            expected = step(expected)
        assert rt.random.random_data == expected, "the refusal drew nothing"

    def test_refused_calls_do_not_count(self, rt):
        for _ in range(300):
            dice(rt, 0)
            util_random(rt, 0, 0)
        assert rt._rng_draws == 0


class TestDiceRejectionSampling:
    """The rejection path cannot be reached through a real hash — a rejected
    word lies within `sides - 1` of 2^64 — so the block is supplied."""

    @pytest.fixture
    def drawn(self, rt, monkeypatch):
        def supply(block: bytes):
            monkeypatch.setattr(rng, "_rng_next", lambda _rt, _api: block)
        return supply

    def test_a_rejected_word_falls_through_to_the_next(self, rt, drawn):
        # sides 3: 2^64 mod 3 == 1, so only 2^64 - 1 is rejected
        drawn((U64_MAX).to_bytes(8, "big") + (10).to_bytes(8, "big")
              + bytes(16))
        assert dice(rt, 3) == 10 % 3

    def test_a_fully_rejected_block_is_rehashed(self, rt, drawn):
        block = b"\xFF" * 32
        drawn(block)
        nxt = H(block)
        word = int.from_bytes(nxt[0:8], "big")
        assert word <= U64_MAX - 1
        assert dice(rt, 3) == word % 3

    def test_sixteen_rejected_blocks_fall_back_to_the_last_word(
            self, rt, drawn, monkeypatch):
        drawn(b"\xFF" * 32)
        monkeypatch.setattr(rng, "_sha512_half", lambda _data: b"\xFF" * 32)
        assert dice(rt, 3) == U64_MAX % 3 == 0

    def test_a_power_of_two_accepts_every_word(self, rt, drawn):
        drawn(b"\xFF" * 32)
        assert dice(rt, 2**31) == U64_MAX % 2**31

    def test_one_side(self, rt):
        assert dice(rt, 1) == 0


# ---------------------------------------------------------------------------
# Through rt.run — the RNG_test hooks, from the WAT in their comments
# ---------------------------------------------------------------------------

_HEAD = """(module
  (import "env" "_g" (func $_g (param i32 i32) (result i32)))
  (import "env" "accept" (func $accept (param i32 i32 i64) (result i64)))
  (import "env" "rollback" (func $rollback (param i32 i32 i64) (result i64)))
  (import "env" "dice" (func $dice (param i32) (result i64)))
  (import "env" "util_random" (func $util_random (param i32 i32) (result i64)))
  (memory 1)
"""


def _hook(body: str, export: str = "hook") -> bytes:
    return bytes(wasmtime.wat2wasm(
        _HEAD
        + f"  (func ${export} (param i32) (result i64)\n"
        + "    (drop (call $_g (i32.const 1) (i32.const 1)))\n"
        + f"    {body})\n"
        + '  (export "memory" (memory 0))\n'
        + f'  (export "{export}" (func ${export})))'))


DICE6 = _hook("(call $accept (i32.const 0) (i32.const 0) "
              "(call $dice (i32.const 6)))")
DICE0 = _hook("(call $accept (i32.const 0) (i32.const 0) "
              "(call $dice (i32.const 0)))")
DICE_MAX = _hook("(call $accept (i32.const 0) (i32.const 0) "
                 "(call $dice (i32.const -1)))")
DICE_TWICE = _hook(
    "(call $accept (i32.const 0) (i32.const 0) (i64.extend_i32_u (i64.eq "
    "(call $dice (i32.const -1)) (call $dice (i32.const -1)))))")
DICE_ROLLBACK = _hook("(call $rollback (i32.const 0) (i32.const 0) "
                      "(call $dice (i32.const -1)))")


def _util_random(n: int) -> bytes:
    return _hook("(call $accept (i32.const 0) (i32.const 0) "
                 f"(call $util_random (i32.const 0) (i32.const {n})))")


@pytest.fixture
def chain() -> HookRuntime:
    r = HookRuntime()
    r.amendments.add("featureRNG")
    r.seed_random(STATE)
    r.hook_account = ACCOUNT
    r.otxn_id_val = TXID
    return r


class TestThroughRun:
    """xahaud:src/test/app/RNG_test.cpp:865 — "the individual APIs"."""

    def test_no_entropy(self):
        rt = HookRuntime()
        rt.amendments.add("featureRNG")
        result = rt.run(DICE6)
        assert result.return_code == hookapi.TOO_LITTLE_ENTROPY
        assert result.random_data is None

    def test_dice_six(self, chain):
        assert 0 <= chain.run(DICE6).return_code < 6

    def test_dice_zero(self, chain):
        assert chain.run(DICE0).return_code == hookapi.INVALID_ARGUMENT

    def test_dice_max_sides_is_unsigned(self, chain):
        result = chain.run(DICE_MAX)
        assert result.error is None
        assert 0 <= result.return_code < 0xFFFFFFFF

    def test_two_draws_differ(self, chain):
        assert chain.run(DICE_TWICE).return_code == 0

    @pytest.mark.parametrize("n,code", [
        (32, 32), (0, hookapi.TOO_SMALL), (513, hookapi.TOO_BIG)])
    def test_util_random(self, chain, n, code):
        assert chain.run(_util_random(n)).return_code == code

    def test_the_hook_hash_is_the_module_hash(self, chain):
        result = chain.run(_util_random(32))
        assert result.random_draws[0].output == out(
            hook_hash=H(_util_random(32)), position=0)

    def test_a_configured_hook_hash_wins(self, chain):
        chain.hook_hash = HOOK_HASH
        result = chain.run(_util_random(32))
        assert result.random_draws[0].output == out(position=0)

    def test_the_draw_counter_resets_per_run(self, chain):
        chain.run(DICE6)
        assert chain._rng_draws == 1
        chain.run(DICE6)
        assert chain._rng_draws == 1

    def test_weak_execution(self, chain):
        result = chain.run(_util_random(32), arg=1)
        assert result.random_draws[0].output == out(
            hook_hash=H(_util_random(32)), position=0, strong=0, wasm_param=1)

    def test_not_applied_callback(self, chain):
        """The applied transaction is the ttEMIT_FAILURE pseudo-transaction,
        whose ID hookz cannot derive — the test supplies it."""
        from hookz import CALLBACK_NOT_APPLIED

        cbak = bytes(wasmtime.wat2wasm(_HEAD + """
  (func $hook (param i32) (result i64) (i64.const 0))
  (func $cbak (param i32) (result i64)
    (call $accept (i32.const 0) (i32.const 0)
      (call $util_random (i32.const 0) (i32.const 32))))
  (export "memory" (memory 0))
  (export "hook" (func $hook))
  (export "cbak" (func $cbak)))"""))
        chain.applied_txn_id = b"\x5A" * 32
        from hookz.xrpl.txn_builder import serialize_fields
        emission = serialize_fields({hookapi.sfTransactionType: (0).to_bytes(2, "big"),
                                     hookapi.sfAccount: b"\x11" * 20})
        result = chain.run_callback(cbak, emitted_tx=emission, tx_hash=b"\xE7" * 32,
                                    ctx=CALLBACK_NOT_APPLIED)
        assert result.return_code == 32
        assert result.random_draws[0].output == out(
            txid=b"\x5A" * 32, hook_hash=H(cbak), position=0,
            strong=0, callback=1, wasm_param=1)
        assert result.random_draws[0].export == "cbak"

    def test_outside_run_the_hook_hash_must_be_set(self, rt):
        rt.hook_hash = None
        with pytest.raises(RuntimeError, match="rt.hook_hash"):
            dice(rt, 6)


class TestTheAdvanceIsDurable:
    def test_a_rolled_back_hook_keeps_its_draws(self, chain):
        """xahaud:src/test/app/RNG_test.cpp:827 — the next draw carries on
        from where the rolled-back hook left the state."""
        rolled = chain.run(DICE_ROLLBACK)
        assert rolled.rejected
        assert rolled.random_data == STATE
        assert chain.random.random_data == step(STATE)

        nxt = chain.run(DICE_MAX)
        assert nxt.random_data == step(STATE)
        assert chain.random.random_data == step(step(STATE))

    def test_two_hooks_in_one_chain_see_successive_states(self, chain):
        """xahaud:src/test/app/RNG_test.cpp:808 — two hooks on one account,
        one draw each, return different values."""
        chain.hook_chain_position = 0
        first = chain.run(DICE_MAX)
        chain.hook_chain_position = 1
        second = chain.run(DICE_MAX)

        assert first.random_data == STATE
        assert second.random_data == step(STATE)
        assert first.return_code != second.return_code

    def test_random_data_is_the_first_draw_only(self, chain):
        result = chain.run(DICE_TWICE)
        assert [d.state for d in result.random_draws] == [STATE, step(STATE)]
        assert result.random_data == STATE

    def test_a_refused_draw_is_not_recorded(self, chain):
        assert chain.run(DICE0).random_draws == []


class TestRandomState:
    def test_the_state_is_32_bytes(self):
        with pytest.raises(ValueError, match="32-byte"):
            RandomState(random_data=b"\x00" * 31, ledger_seq=1)

    def test_counts_are_uint16(self):
        with pytest.raises(ValueError, match="UInt16"):
            RandomState(random_data=STATE, ledger_seq=1, entropy_count=0x10000)

    def test_a_bad_state_set_later_is_caught_at_the_draw(self, rt):
        rt.random.random_data = b"short"
        with pytest.raises(ValueError, match="32-byte"):
            dice(rt, 6)

    def test_seed_random_returns_the_live_object(self, rt):
        state = rt.seed_random(b"\x11" * 32, entropy_count=4,
                               entropy_denominator=5)
        assert rt.random is state
        assert (state.ledger_seq, state.entropy_count,
                state.entropy_denominator) == (rt.ledger_seq_val, 4, 5)
