# Lean Contract Evolution Loop

This is the working process for adding theorem-backed development contracts to
the existing hook suite. The goal is not to compile Lean into hooks. The goal is
to use Python hook execution as the concrete witness and Lean as the pure
contract/model layer that those executions are checked against.

## Starting Assumptions

- Hooks are procedural programs over a host world, not collections of small pure
  functions.
- The C source is macro-heavy, so the first useful theorem boundary is usually
  not a C function boundary.
- Python tests already build the meaningful world state: transaction type,
  hook account, origin account, hook params, ledger entries, state entries, and
  expected emitted transactions.
- Lean should see a distilled semantic record, not the whole `HookRuntime`.
- projected-source can provide the literate layer by projecting from C, Python,
  and Lean files without making prose the source of truth.

## Maturity Levels

Each hook can climb these levels independently.

1. **L0 inventory**: list the semantic inputs, observed outputs, and host-world
   effects the existing pytest cases care about.
2. **L1 pure model**: add a sister Lean model with an `Input` structure,
   `expected` function, and local theorems.
3. **L2 checked examples**: mirror the existing pytest cases as Lean examples.
   These may be hand-written first, then generated from Python once the shape is
   stable.
4. **L3 Python adapter**: add a Python adapter that snapshots the runtime before
   and after execution and emits Lean cases from the actual run.
5. **L4 literate contract**: render a projected-source page that shows the C
   region, Python adapter/test, Lean model, and theorem cases together.
6. **L5 CI gate**: run pytest, `lake build`, and projected-source validation.

Do not push a hook to the next level until the notes from the previous level
are clear enough to reuse on the next hook.

## Per-Hook Loop

For each hook in `tests/e2e/hookz.toml`:

1. Read the C hook and the existing pytest class that exercises it.
2. Write an inventory:
   - pre-state fields read by the hook
   - hook params read
   - transaction fields read
   - ledger slots/keylets read
   - state keys read/written
   - emitted transaction count or shape
   - accept/reject result and message predicates
3. Define the smallest Lean `Input` record that can explain the behavior under
   test.
4. Define the smallest Lean `Outcome` or reuse `Verdict` when accept/reject is
   enough.
5. Write `expected : Input -> Outcome`.
6. Add two kinds of theorem:
   - branch theorems, such as "outgoing accepts" or "missing state rejects"
   - concrete examples that mirror existing pytest cases
7. After one or two hooks have stable shapes, add Python case generation. The
   generator should gather inputs imperatively from `HookRuntime` because that
   is where the hook world actually exists.
8. Render a projected-source page for the hook when the Lean and Python surfaces
   stop moving.
9. Record one short retrospective:
   - what the Lean input hid too much or exposed too much
   - what Python had to infer from the world
   - what should be promoted to common Lean vocabulary

## Representative Order

The hooks in `tests/e2e/hookz.toml` give a good growth path:

1. `balance_gate`: ledger lookup plus pass/reject boundary, no emitted txns.
2. `accept_incoming_xah` and `reject_incoming_xah`: minimal transaction-shape
   predicates.
3. `state_counter`: persistent state update and owner-gated invoke path.
4. `state_toggle`: stateful enable/disable gate with payment behavior.
5. `mint`: parameter validation plus one emitted transaction.
6. `multi_invoke_emit`: state-configured fanout and emitted transaction count.
7. `treasury`: params, ledger checks, cooldown state, emitted transaction, and
   state write.
8. `reward`: time/ledger delay, state membership, ledger fields, and emitted
   reward.
9. `govern`: large state machine; only approach after the common vocabulary has
   emerged from the smaller hooks.

The XahauHooks101 remit examples should be sampled after `mint` and
`multi_invoke_emit`, not before. They mostly stress emitted transaction shape.

## First Specimen Notes: balance_gate

`balance_gate.c` is a useful first hook because the semantic model is smaller
than the hook world:

- `outgoing`: derived by Python from `rt.hook_account == rt.otxn_account`
- `senderBalanceDrops`: derived by Python from the ledger account root lookup,
  represented as `none` when the sender cannot be loaded
- `minBalanceDrops`: derived by Python from `MIN_BAL` or the default value
- output: `accept` or `reject`

The Lean model intentionally ignores keylet bytes, slots, XFL encoding, and
message contents. Those belong in Python adapter tests unless/until a later hook
shows they need theorem-level vocabulary.

## Current Specimens

The branch currently carries four specimen models:

- `BalanceGate`: accept/reject model over outgoing status, optional sender
  balance, and minimum balance.
- `BasicNative`: two simple incoming-XAH teaching hooks modeled over outgoing
  status and amount kind.
- `StateCounter`: state transition model over transaction kind, owner status,
  existing counter state, and optional counter parameter.
- `StateToggle`: owner-gated state mutation with payment paths that always
  accept while preserving toggle state.
- `Mint`: coarse emitted-transaction model over presence of `sfBlob`.
- `MultiInvokeEmit`: state-configured fanout model that keeps only destination
  presence and emitted transaction count, not emitted transaction bytes.

The contrast is intentional. `BalanceGate` proves a decision predicate,
`BasicNative` proves pure transaction classification, `StateCounter` proves a
state update, `Mint` proves a one-emission boundary, and `MultiInvokeEmit`
proves count-based fanout. These are the first vocabularies to stress before
adding generated cases.

## Projected-Source Shape

A contract page should be a `.md.j2` template, not the authoritative source.
Use symbolic extraction first and markers only when a whole function is too
large:

```jinja
{{ code('tests/e2e/hooks/misc/balance_gate.c', function='hook') }}
{{ code('lean/Hookz/Contracts/BalanceGate.lean', function='expected') }}
{{ code('lean/Hookz/Contracts/BalanceGate.lean', function='outgoing_accepts') }}
{{ code('tests/e2e/test_balance_gate.py', function='TestBalanceGatePass.test_sender_exactly_at_minimum') }}
```

When a hook function becomes too large for useful projection, add source markers
around the decision region:

```c
//@@start balance-check
...
//@@end balance-check
```

Lean files use the corresponding Lean marker syntax:

```lean
-- @@start model
...
-- @@end model
```
