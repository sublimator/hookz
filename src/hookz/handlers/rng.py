"""On-chain randomness (featureRNG) — dice, util_random.

Host sources:
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1936   (rng_next — the draw)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1995   (dice)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2028   (util_random)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:2887 (dice wrapper)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:2909 (util_random wrapper)
Ported behaviour tests: the individual APIs
(xahaud:src/test/app/RNG_test.cpp:865), no entropy
(xahaud:src/test/app/RNG_test.cpp:727), and a tec keeping its draws
(xahaud:src/test/app/RNG_test.cpp:827).

Both APIs draw a 32-byte block from the ledger's RNG state (`rt.random`, a
`RandomState`; see `HookRuntime.seed_random`) and differ only in what they
make of it. Every draw is a pure function of the state and of the execution
that made it, so the emulation is deterministic: the same `RandomState` and
the same execution give the same bytes, run after run. What it cannot give is
the bytes a ledger would: on chain the state comes from validator reveals
(xahaud:src/xrpld/app/tx/detail/Change.cpp:340), which no test can know in
advance.

The draw (`_rng_next`), in the host's order:

1. `featureRNG` not enabled -> TOO_LITTLE_ENTROPY
   (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1944). It is `DefaultNo` and
   the vendored mainnet manifest does not carry it, so a default runtime
   answers -46 here; `rt.amendments.add("featureRNG")`.
2. 256 draws already made by this execution -> TOO_MANY_NONCES
   (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1947,
   xahaud:include/xrpl/hook/Enum.h:404). The counter is per execution
   (xahaud:src/xrpld/app/hook/applyHook.h:214), so `run` resets it.
3. No Random object (`rt.random is None`) -> TOO_LITTLE_ENTROPY
   (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1951). The default, and the
   chain's answer on a ledger no ttENTROPY round has seeded.
4. Seeded for a ledger other than this one (`ledger_seq != rt.ledger_seq_val`)
   -> TOO_LITTLE_ENTROPY (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1959).
   That line also lets an *open* ledger draw on the previous ledger's seed
   (`view.open() && seededFor + 1 == seq`); hookz applies as a closed ledger
   does, so that preview exception is not modelled.
5. `entropy_count == 0 || entropy_count * 5 < entropy_denominator * 4` ->
   TOO_LITTLE_ENTROPY (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1967).
6. Otherwise, with `state` the current `random_data`:

       out    = sha512Half('RNGO', state, txid, hook account, hook hash,
                           u8 chain position, u8 strong, u8 callback,
                           u32 wasmParam)
       state' = sha512Half('RNGI', state)

   (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1976,
   xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1987), and the draw counter
   increments only now (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1990).

Byte layout of those hashes, which is the whole of what "deterministic"
promises. `sha512Half` feeds each argument through `hash_append` into a
hasher declared big-endian (xahaud:include/xrpl/protocol/digest.h:176), so
every integer is byte-reversed on a little-endian host
(xahaud:include/xrpl/beast/hash/hash_append.h:249) — big-endian on any host —
while a `uint256`/`AccountID` is appended as its raw bytes with no endian
transformation (xahaud:include/xrpl/basics/base_uint.h:501). The tags are
`uint32_t` 0x524E474F / 0x524E4749
(xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1938), so big-endian they are
the ASCII `RNGO` / `RNGI`. The output preimage is therefore exactly 127 bytes:

    b"RNGO" | state[32] | txid[32] | account[20] | hook_hash[32]
            | chain_pos[1] | strong[1] | callback[1] | wasm_param[4, big-endian]

What each input is here — derived wherever the runtime already knows it:

* `txid` — the transaction being applied
  (`applyCtx.tx.getTransactionID()`): `rt.applied_txn_id` if set, else what
  `otxn_id` serves (`rt.otxn_id_val`, or its sentinel fill). The two agree
  except in a *not-applied* callback, where the applied transaction is the
  ttEMIT_FAILURE pseudo-transaction and its own ID — which hookz does not
  derive — is hashed, not the failed emission's; set `rt.applied_txn_id`
  there if the exact bytes matter.
* `account` — `rt.hook_account`, the account the hook is installed on.
* `hook_hash` — `rt.hook_hash` if set, else sha512Half of the module bytes
  `run` was handed (before any coverage instrumentation), which is how
  SetHook names a hook (xahaud:src/xrpld/app/tx/detail/SetHook.cpp:1832).
  The `hook_hash` *host function* is still a stub serving zeros; it does not
  consult this.
* `chain_pos` — `rt.hook_chain_position`, the hook's index in the account's
  Hooks array, blanks included: the chain counts `hook_no` before it skips a
  blank and passes `hook_no - 1`
  (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1388,
  xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1474).
* `strong`, `callback`, `wasm_param` — derived from the run, not configured.
  `wasmParam` is the argument the export is called with
  (xahaud:src/xrpld/app/hook/applyHook.h:452), i.e. `run(..., arg=)`. The
  chain calls `hook` with 0 strong / 1 weak
  (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1473) or 2 again-as-weak
  (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1961), and only the first
  is strong; it calls `cbak` non-strong with 0 applied / 1 not applied
  (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1645,
  xahaud:src/xrpld/app/tx/detail/Transactor.cpp:1646). So `callback` is
  `export == "cbak"` and `strong` is `not callback and arg == 0`.

Durability. The state advance is never undone: a transaction that ends in a
tec (a rolled-back hook) keeps it (xahaud:src/xrpld/app/tx/detail/ApplyContext.cpp:74),
so `rt.random` advances whatever the run's outcome — it is not reverted with
anything. The state the transaction's *first* draw saw is what its final
metadata records as sfRandomData
(xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1973,
xahaud:src/xrpld/ledger/ApplyViewImpl.h:136); per run that is
`result.random_data`, and every draw is on `result.random_draws`.

What hooks cannot do is read the state: `slot_set` and `ledger_keylet` refuse
the Random object (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2315,
xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2065). Keeping it on
`rt.random` rather than in `rt.ledger` is how that holds here — no hook-facing
lookup consults `rt.random`.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from hookz import hookapi
from hookz.handlers.core import _not_in_bounds

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

# xahaud:include/xrpl/hook/Enum.h:404 — per hook execution
MAX_RNG_DRAWS = 256
# xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2033
MAX_RANDOM_BYTES = 512
# dice's rejection-sampling bound, in 32-byte blocks
# (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2012)
_DICE_BLOCKS = 16

# The uint32_t tags, big-endian (see the module docstring for why).
_RNG_OUTPUT_TAG = (0x524E474F).to_bytes(4, "big")   # b"RNGO"
_RNG_STEP_TAG = (0x524E4749).to_bytes(4, "big")     # b"RNGI"

_U64_MAX = (1 << 64) - 1


def _sha512_half(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()[:32]


def _hook_hash(rt: HookRuntime) -> bytes:
    """The executing hook's HookHash — configured, or derived from the module."""
    if rt.hook_hash is not None:
        if len(rt.hook_hash) != 32:
            raise ValueError(
                f"rt.hook_hash must be a 32-byte Hash256, got "
                f"{len(rt.hook_hash)} bytes")
        return bytes(rt.hook_hash)
    if rt._run_hook_hash is None:
        if rt._run_wasm is None:
            raise RuntimeError(
                "a featureRNG draw hashes the executing hook's HookHash, and "
                "this call is not inside rt.run(), so there are no module "
                "bytes to derive it from — set rt.hook_hash")
        rt._run_hook_hash = _sha512_half(bytes(rt._run_wasm))
    return rt._run_hook_hash


def _applied_txn_id(rt: HookRuntime) -> bytes:
    """`applyCtx.tx.getTransactionID()`, as far as the runtime knows it."""
    from hookz.handlers.otxn import _OTXN_ID_SENTINEL

    for name in ("applied_txn_id", "otxn_id_val"):
        value = getattr(rt, name)
        if value is not None:
            if len(value) != 32:
                raise ValueError(
                    f"rt.{name} must be a 32-byte Hash256, got "
                    f"{len(value)} bytes")
            return bytes(value)
    return _OTXN_ID_SENTINEL


def _execution_inputs(rt: HookRuntime) -> bytes:
    """Everything after the state in the output preimage (95 bytes)."""
    account = bytes(rt.hook_account)
    if len(account) != 20:
        raise ValueError(
            f"rt.hook_account must be a 20-byte AccountID, got "
            f"{len(account)} bytes")
    position = rt.hook_chain_position
    if not 0 <= position <= 0xFF:
        raise ValueError(
            f"rt.hook_chain_position is a uint8_t index into the Hooks "
            f"array, got {position}")
    callback = rt._current_export == "cbak"
    wasm_param = rt._current_arg & 0xFFFFFFFF
    strong = not callback and wasm_param == 0
    return (
        _applied_txn_id(rt)
        + account
        + _hook_hash(rt)
        + bytes([position, 1 if strong else 0, 1 if callback else 0])
        + wasm_param.to_bytes(4, "big")
    )


def _rng_next(rt: HookRuntime, api: str) -> int | bytes:
    """One draw: the 32-byte block, or the host's refusal code.

    Refusals consume nothing — neither the state nor the per-execution count.
    """
    from hookz.runtime import RandomDraw

    if "featureRNG" not in rt.amendments:
        return hookapi.TOO_LITTLE_ENTROPY
    if rt._rng_draws >= MAX_RNG_DRAWS:
        return hookapi.TOO_MANY_NONCES
    random = rt.random
    if random is None:
        return hookapi.TOO_LITTLE_ENTROPY
    random._check()
    if random.ledger_seq != rt.ledger_seq_val:
        return hookapi.TOO_LITTLE_ENTROPY
    count = random.entropy_count
    if count == 0 or count * 5 < random.entropy_denominator * 4:
        return hookapi.TOO_LITTLE_ENTROPY

    state = bytes(random.random_data)
    out = _sha512_half(_RNG_OUTPUT_TAG + state + _execution_inputs(rt))
    random.random_data = _sha512_half(_RNG_STEP_TAG + state)
    rt._rng_draws += 1
    rt._random_draws.append(RandomDraw(
        api=api, state=state, output=out, export=rt._current_export))
    return out


def dice(rt: HookRuntime, sides: int) -> int:
    """A uniform integer in [0, sides).

    `sides == 0` is refused before any draw
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1997). Otherwise the block
    is read as four big-endian u64 words and the first one at or below
    `2^64 - 1 - (2^64 mod sides)` is reduced mod `sides`
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2009,
    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2019); if all four are
    rejected the block is rehashed and read again, up to 16 blocks
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2022), after which the last
    word read is reduced regardless
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2024). A rejection needs a
    word within `sides - 1` of 2^64, so with a u32 `sides` the fallback is
    unreachable in practice and only bounds the loop.
    """
    if sides == 0:
        return hookapi.INVALID_ARGUMENT
    block = _rng_next(rt, "dice")
    if isinstance(block, int):
        return block
    excess = (_U64_MAX % sides + 1) % sides     # 2^64 mod sides
    limit = _U64_MAX - excess
    word = 0
    for _ in range(_DICE_BLOCKS):
        for w in range(4):
            word = int.from_bytes(block[w * 8:(w + 1) * 8], "big")
            if word <= limit:
                return word % sides
        block = _sha512_half(block)
    return word % sides


def util_random(rt: HookRuntime, write_ptr: int, write_len: int) -> int:
    """`write_len` (1..512) random bytes, written to the hook; returns the count.

    The wrapper checks the buffer's bounds first
    (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:2909), then the API
    refuses a zero or oversized length — TOO_SMALL, TOO_BIG — before drawing
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2030,
    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2033), so none of the three
    consumes a draw. The bytes are the block, then its hash, then that hash's
    hash, … truncated to `write_len`
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2045,
    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2049), and the wrapper
    returns the number written (xahaud:src/xrpld/app/hook/detail/applyHook.cpp:2918).
    """
    if _not_in_bounds(rt, write_ptr, write_len):
        return hookapi.OUT_OF_BOUNDS
    if write_len == 0:
        return hookapi.TOO_SMALL
    if write_len > MAX_RANDOM_BYTES:
        return hookapi.TOO_BIG
    block = _rng_next(rt, "util_random")
    if isinstance(block, int):
        return block
    out = bytearray()
    while True:
        out += block[:write_len - len(out)]
        if len(out) >= write_len:
            break
        block = _sha512_half(block)
    rt._write_memory(write_ptr, bytes(out))
    return write_len
