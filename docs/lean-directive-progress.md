# Lean Directive Progress Notes

## Current Direction

Lean directives are a development layer. Production hook builds still see only C
comments. Dev builds unwrap selected `hookz:` comment blocks into host calls,
capture semantic values at a checkpoint, and fail fast by dispatching those
captures to Lean during hook execution.

## Iteration: `balance_gate.after_decision`

`balance_gate.c` is the first repo-owned hook with a real hook-local checkpoint.
The source directive uses the short checkpoint name:

```c
/* hookz:
HOOKZ_LEAN4_U64("outgoing", 0);
HOOKZ_LEAN4_I64("sender_balance_xfl", balance);
HOOKZ_LEAN4_I64("min_balance_xfl", min_balance);
HOOKZ_LEAN4_U64("verdict_accept", 1);
HOOKZ_LEAN4_CHECK("after_decision");
*/
```

At runtime, `HookRuntime` supplies the hook source path. The dev Lean dispatcher
uses `hookz.toml` to resolve that local checkpoint to
`balance_gate.after_decision` and imports the configured Lean root:

```toml
balance_gate = { source = "hooks/misc/balance_gate.c", lean = "hooks/misc/balance_gate.lean" }
```

The colocated `hooks/misc/balance_gate.lean` file is treated as the hook's Lean
root/index. Since it lives outside the main `lean/` Lake source root, the dev
dispatcher compiles it into a generated sidecar `.olean` under the witness output
directory and imports that generated module from the witness.

## Emerging Pattern

- C directives should capture semantic facts, not raw host-world blobs.
- Python adapters should perform encoding/decoding that C and Lean do not need
  to share. For `balance_gate`, the adapter converts captured XFL values into
  integer drop amounts before generating the Lean witness.
- Short checkpoint names are better in source. The hook name and Lean root come
  from config.
- `lean = "...path..."` is now path-first for repo-local files. Files under
  `lean/` import directly by module path; colocated sidecars compile to a
  generated dev module before the witness imports them.
- Repo-owned hooks can carry inline directives. Vendored/submodule hook sources
  should stay untouched until there is an overlay mechanism.
- Coverage remains a development concern too. Dev-generated C uses `#line`
  markers so DWARF line numbers stay mapped to the original hook source.
- XFL captures for integer amounts are decoded by mantissa/exponent in Python so
  Lean witnesses do not depend on Python float rounding.

## Bug-Catching Specimen

`tests/test_dev_directives.py` includes a deliberately buggy temporary hook that
claims an incoming account with `5_000_000` drops satisfies a `10_000_000` drop
minimum. The C hook would call `accept`, but the
`balance_gate.after_decision` checkpoint dispatches first and Lean rejects the
generated witness. This is the smallest current proof that the directive layer
can catch a bad hook decision before the hook finishes.

## Next Candidates

1. `mint`: checkpoint before emit with presence/absence of `sfBlob`.
2. `treasury`: branch checkpoints for claim setup, claim, and release.
3. `reward`: claim eligibility and emit boundary.
4. `state_counter`: convert the synthetic test checkpoint into a source-local
   short tag once there is a non-submodule specimen or overlay path.
