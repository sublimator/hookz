"""Lean dev adapters for the e2e hook tests."""

from hookz.dev_lean import (
    DevCheckContext,
    bool_literal,
    capture_optional_i64,
    capture_u64,
    import_module,
    register_dev_lean_adapter,
    verdict_literal,
    xfl_int_literal,
)


def _balance_gate_after_decision(
    captures: dict[str, dict],
    context: DevCheckContext,
) -> str:
    outgoing = capture_u64(captures, "outgoing") != 0
    accepted = capture_u64(captures, "verdict_accept") != 0
    sender_balance_xfl = capture_optional_i64(captures, "sender_balance_xfl")
    min_balance_xfl = capture_optional_i64(captures, "min_balance_xfl")
    sender_balance = (
        "none"
        if sender_balance_xfl is None
        else f"some {xfl_int_literal(sender_balance_xfl)}"
    )
    min_balance = (
        10000000
        if min_balance_xfl is None
        else xfl_int_literal(min_balance_xfl)
    )
    lean_import = import_module(context, "Hookz.Contracts.BalanceGate")
    model_module = "Hookz.Contracts.BalanceGate"
    return f"""import {lean_import}

open Hookz.Contracts

-- generated from hookz dev checkpoint: balance_gate.after_decision
example :
    {model_module}.expected {{
      outgoing := {bool_literal(outgoing)},
      senderBalanceDrops := {sender_balance},
      minBalanceDrops := {min_balance}
    }} = {verdict_literal(accepted)} := by
  native_decide
"""


def _mint_after_decision(
    captures: dict[str, dict],
    context: DevCheckContext,
) -> str:
    has_blob = capture_u64(captures, "has_blob") != 0
    emitted_count = capture_u64(captures, "emitted_count")
    accepted = capture_u64(captures, "verdict_accept") != 0
    lean_import = import_module(context, "Hookz.Contracts.Mint")
    model_module = "Hookz.Contracts.Mint"
    return f"""import {lean_import}

open Hookz.Contracts

-- generated from hookz dev checkpoint: mint.after_decision
example :
    {model_module}.expected {{
      hasBlob := {bool_literal(has_blob)}
    }} = {{ verdict := {verdict_literal(accepted)}, emittedCount := {emitted_count} }} := by
  native_decide
"""


def register_lean_adapters() -> None:
    register_dev_lean_adapter(
        "balance_gate.after_decision",
        _balance_gate_after_decision,
    )
    register_dev_lean_adapter("mint.after_decision", _mint_after_decision)
