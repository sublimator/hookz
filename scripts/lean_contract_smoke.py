#!/usr/bin/env python3
"""Crude Python-to-Lean contract smoke check.

This is intentionally narrow: run a few real hook executions, distill
HookRuntime state into Lean input shapes, generate Lean examples asserting the
models match observed hook outcomes, and ask Lean to check the generated file.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from xrpl.core.binarycodec import decode

from hookz import hookapi
from hookz.compiler import compile_hook
from hookz.config import load_config
from hookz.ledger import account_root, account_root_keylet
from hookz.runtime import HookRuntime
from hookz.xfl import float_to_xfl, xfl_to_float


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MIN_BALANCE_DROPS = 10_000_000

ALICE = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
BOB = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"

ALICE_ACCID = bytes.fromhex("b5f762798a53d543a014caf8b297cff8f2f937e8")
BOB_ACCID = bytes.fromhex("f667b0ca50cc7709a220b0561b85e53a48461fa8")


@dataclass
class BalanceGateInput:
    outgoing: bool
    sender_balance_drops: int | None
    min_balance_drops: int


@dataclass
class BalanceGateCase:
    name: str
    input: BalanceGateInput
    verdict: str


@dataclass
class StateCounterInput:
    tx_kind: str
    owner: bool
    counter_state: int | None
    counter_param: int | None


@dataclass
class StateCounterOutcome:
    verdict: str
    counter_state: int | None


@dataclass
class StateCounterCase:
    name: str
    input: StateCounterInput
    outcome: StateCounterOutcome


def _base_runtime() -> HookRuntime:
    rt = HookRuntime()
    rt.hook_account = ALICE_ACCID
    rt.otxn_account = BOB_ACCID
    rt.otxn_type = hookapi.ttPAYMENT
    return rt


def _noop(_rt: HookRuntime) -> None:
    pass


def _put_account_balance(rt: HookRuntime, account: str, balance_drops: int) -> None:
    keylet, data = account_root(account, Balance=str(balance_drops))
    rt.ledger[keylet] = data


def _set_min_balance(rt: HookRuntime, min_balance_drops: int) -> None:
    rt.params[b"MIN_BAL"] = struct.pack("<q", float_to_xfl(float(min_balance_drops)))


def _sender_balance_from_ledger(rt: HookRuntime) -> int | None:
    keylet = account_root_keylet(rt.otxn_account)
    data = rt.ledger.get(keylet)
    if data is None:
        return None
    decoded = decode(data.hex())
    balance = decoded.get("Balance")
    return int(balance) if balance is not None else None


def _min_balance_from_params(rt: HookRuntime) -> int:
    raw = rt.params.get(b"MIN_BAL")
    if raw is None or len(raw) != 8:
        return DEFAULT_MIN_BALANCE_DROPS
    xfl = struct.unpack("<q", raw)[0]
    return int(xfl_to_float(xfl))


def _u64_be(raw: bytes | None) -> int | None:
    if raw is None or len(raw) != 8:
        return None
    return struct.unpack(">Q", raw)[0]


def _set_counter_state(rt: HookRuntime, value: int) -> None:
    rt.state_db[b"CNT"] = struct.pack(">Q", value)


def _set_counter_param(rt: HookRuntime, value: int) -> None:
    rt.params[b"CNT"] = struct.pack(">Q", value)


def _make_owner(rt: HookRuntime) -> None:
    rt.otxn_account = rt.hook_account


def _make_invoke(rt: HookRuntime) -> None:
    rt.otxn_type = hookapi.ttINVOKE


def _make_other_tx(rt: HookRuntime) -> None:
    rt.otxn_type = hookapi.ttTRUST_SET


def _configure_owner_invoke_set_counter(rt: HookRuntime) -> None:
    _make_invoke(rt)
    _make_owner(rt)
    _set_counter_param(rt, 42)
    _set_counter_state(rt, 5)


def _configure_owner_invoke_missing_param(rt: HookRuntime) -> None:
    _make_invoke(rt)
    _make_owner(rt)


def gather_balance_gate_input(rt: HookRuntime) -> BalanceGateInput:
    return BalanceGateInput(
        outgoing=rt.hook_account == rt.otxn_account,
        sender_balance_drops=_sender_balance_from_ledger(rt),
        min_balance_drops=_min_balance_from_params(rt),
    )


def _tx_kind(rt: HookRuntime) -> str:
    if rt.otxn_type == hookapi.ttPAYMENT:
        return "payment"
    if rt.otxn_type == hookapi.ttINVOKE:
        return "invoke"
    return "other"


def gather_state_counter_input(rt: HookRuntime) -> StateCounterInput:
    return StateCounterInput(
        tx_kind=_tx_kind(rt),
        owner=rt.hook_account == rt.otxn_account,
        counter_state=_u64_be(rt.state_db.get(b"CNT")),
        counter_param=_u64_be(rt.params.get(b"CNT")),
    )


def gather_state_counter_outcome(rt: HookRuntime, verdict: str) -> StateCounterOutcome:
    return StateCounterOutcome(
        verdict=verdict,
        counter_state=_u64_be(rt.state_db.get(b"CNT")),
    )


def _verdict(result) -> str:
    if result.accepted:
        return "accept"
    if result.rejected:
        return "reject"
    raise RuntimeError(f"hook did not accept or reject: {result!r}")


def _compile_hook(name: str) -> bytes:
    config = load_config(toml_path=ROOT / "tests" / "e2e" / "hookz.toml")
    assert config.hooks is not None
    return compile_hook(config.hooks[name], config=config)


def _run_balance_gate_case(name: str, hook_wasm: bytes, configure) -> BalanceGateCase:
    rt = _base_runtime()
    configure(rt)
    lean_input = gather_balance_gate_input(rt)
    result = rt.run(hook_wasm, label="balance_gate.c")
    return BalanceGateCase(name=name, input=lean_input, verdict=_verdict(result))


def _run_state_counter_case(name: str, hook_wasm: bytes, configure) -> StateCounterCase:
    rt = _base_runtime()
    configure(rt)
    lean_input = gather_state_counter_input(rt)
    result = rt.run(hook_wasm, label="basic_state_counter.c")
    verdict = _verdict(result)
    return StateCounterCase(
        name=name,
        input=lean_input,
        outcome=gather_state_counter_outcome(rt, verdict),
    )


def _lean_bool(value: bool) -> str:
    return "true" if value else "false"


def _lean_balance(value: int | None) -> str:
    return "none" if value is None else f"some {value}"


def _lean_tx_kind(value: str) -> str:
    return f".{value}"


def _lean_balance_gate_case(case: BalanceGateCase) -> str:
    inp = case.input
    return f"""-- generated from hookz runtime case: {case.name}
example :
    Hookz.Contracts.BalanceGate.expected {{
      outgoing := {_lean_bool(inp.outgoing)},
      senderBalanceDrops := {_lean_balance(inp.sender_balance_drops)},
      minBalanceDrops := {inp.min_balance_drops}
    }} = .{case.verdict} := by
  native_decide
"""


def _lean_state_counter_case(case: StateCounterCase) -> str:
    inp = case.input
    out = case.outcome
    return f"""-- generated from hookz runtime case: {case.name}
example :
    Hookz.Contracts.StateCounter.expected {{
      txKind := {_lean_tx_kind(inp.tx_kind)},
      owner := {_lean_bool(inp.owner)},
      counterState := {_lean_balance(inp.counter_state)},
      counterParam := {_lean_balance(inp.counter_param)}
    }} = {{ verdict := .{out.verdict}, counterState := {_lean_balance(out.counter_state)} }} := by
  native_decide
"""


def generate_lean(
    balance_gate_cases: list[BalanceGateCase],
    state_counter_cases: list[StateCounterCase],
) -> str:
    body = "\n".join(
        [
            *(_lean_balance_gate_case(case) for case in balance_gate_cases),
            *(_lean_state_counter_case(case) for case in state_counter_cases),
        ]
    )
    return f"""import Hookz.Contracts.BalanceGate
import Hookz.Contracts.StateCounter

open Hookz.Contracts

{body}
"""


def _lake_binary() -> str:
    configured = os.environ.get("LAKE")
    if configured:
        return configured
    found = shutil.which("lake")
    if found:
        return found
    elan_lake = Path.home() / ".elan" / "bin" / "lake"
    if elan_lake.exists():
        return str(elan_lake)
    return "lake"


def main() -> int:
    balance_gate_wasm = _compile_hook("balance_gate")
    balance_gate_cases = [
        _run_balance_gate_case(
            "outgoing_always_passes",
            balance_gate_wasm,
            _make_owner,
        ),
        _run_balance_gate_case(
            "sender_exactly_at_minimum",
            balance_gate_wasm,
            lambda rt: _put_account_balance(rt, BOB, 10_000_000),
        ),
        _run_balance_gate_case(
            "sender_below_minimum",
            balance_gate_wasm,
            lambda rt: _put_account_balance(rt, BOB, 5_000_000),
        ),
        _run_balance_gate_case(
            "sender_not_in_ledger",
            balance_gate_wasm,
            _noop,
        ),
        _run_balance_gate_case(
            "custom_min_1_xah",
            balance_gate_wasm,
            lambda rt: (
                _set_min_balance(rt, 1_000_000),
                _put_account_balance(rt, BOB, 5_000_000),
            ),
        ),
    ]

    state_counter_wasm = _compile_hook("state_counter")
    state_counter_cases = [
        _run_state_counter_case(
            "first_payment_sets_counter_to_1",
            state_counter_wasm,
            _noop,
        ),
        _run_state_counter_case(
            "second_payment_increments",
            state_counter_wasm,
            lambda rt: _set_counter_state(rt, 5),
        ),
        _run_state_counter_case(
            "owner_invoke_sets_counter",
            state_counter_wasm,
            _configure_owner_invoke_set_counter,
        ),
        _run_state_counter_case(
            "non_owner_invoke_rejected",
            state_counter_wasm,
            _make_invoke,
        ),
        _run_state_counter_case(
            "owner_invoke_missing_param_rejected",
            state_counter_wasm,
            _configure_owner_invoke_missing_param,
        ),
        _run_state_counter_case(
            "non_payment_non_invoke_accepted",
            state_counter_wasm,
            _make_other_tx,
        ),
    ]

    out_dir = Path(os.environ.get("HOOKZ_LEAN_SMOKE_DIR", "/tmp/hookz-lean-contract-smoke"))
    out_dir.mkdir(parents=True, exist_ok=True)
    lean_file = out_dir / "GeneratedRuntimeCases.lean"
    lean_file.write_text(generate_lean(balance_gate_cases, state_counter_cases))

    cmd = [_lake_binary(), "env", "lean", str(lean_file)]
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode == 0:
        print(f"Lean checked generated cases: {lean_file}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
