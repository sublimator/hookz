#!/usr/bin/env python3
"""Crude Python-to-Lean contract smoke check.

This is intentionally narrow: run a few real balance_gate hook executions,
distill HookRuntime state into the Lean BalanceGate.Input shape, generate Lean
examples asserting the model matches the observed hook verdict, and ask Lean to
check the generated file.
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
class GeneratedCase:
    name: str
    input: BalanceGateInput
    verdict: str


def _base_runtime() -> HookRuntime:
    rt = HookRuntime()
    rt.hook_account = ALICE_ACCID
    rt.otxn_account = BOB_ACCID
    rt.otxn_type = hookapi.ttPAYMENT
    return rt


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


def gather_balance_gate_input(rt: HookRuntime) -> BalanceGateInput:
    return BalanceGateInput(
        outgoing=rt.hook_account == rt.otxn_account,
        sender_balance_drops=_sender_balance_from_ledger(rt),
        min_balance_drops=_min_balance_from_params(rt),
    )


def _verdict(result) -> str:
    if result.accepted:
        return "accept"
    if result.rejected:
        return "reject"
    raise RuntimeError(f"hook did not accept or reject: {result!r}")


def _compile_balance_gate() -> bytes:
    config = load_config(toml_path=ROOT / "tests" / "e2e" / "hookz.toml")
    assert config.hooks is not None
    return compile_hook(config.hooks["balance_gate"], config=config)


def _run_case(name: str, hook_wasm: bytes, configure) -> GeneratedCase:
    rt = _base_runtime()
    configure(rt)
    lean_input = gather_balance_gate_input(rt)
    result = rt.run(hook_wasm, label="balance_gate.c")
    return GeneratedCase(name=name, input=lean_input, verdict=_verdict(result))


def _lean_bool(value: bool) -> str:
    return "true" if value else "false"


def _lean_balance(value: int | None) -> str:
    return "none" if value is None else f"some {value}"


def _lean_case(case: GeneratedCase) -> str:
    inp = case.input
    return f"""-- generated from hookz runtime case: {case.name}
example :
    expected {{
      outgoing := {_lean_bool(inp.outgoing)},
      senderBalanceDrops := {_lean_balance(inp.sender_balance_drops)},
      minBalanceDrops := {inp.min_balance_drops}
    }} = .{case.verdict} := by
  native_decide
"""


def generate_lean(cases: list[GeneratedCase]) -> str:
    body = "\n".join(_lean_case(case) for case in cases)
    return f"""import Hookz.Contracts.BalanceGate

open Hookz.Contracts
open Hookz.Contracts.BalanceGate

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
    hook_wasm = _compile_balance_gate()
    cases = [
        _run_case(
            "outgoing_always_passes",
            hook_wasm,
            lambda rt: setattr(rt, "otxn_account", rt.hook_account),
        ),
        _run_case(
            "sender_exactly_at_minimum",
            hook_wasm,
            lambda rt: _put_account_balance(rt, BOB, 10_000_000),
        ),
        _run_case(
            "sender_below_minimum",
            hook_wasm,
            lambda rt: _put_account_balance(rt, BOB, 5_000_000),
        ),
        _run_case(
            "sender_not_in_ledger",
            hook_wasm,
            lambda rt: None,
        ),
        _run_case(
            "custom_min_1_xah",
            hook_wasm,
            lambda rt: (
                _set_min_balance(rt, 1_000_000),
                _put_account_balance(rt, BOB, 5_000_000),
            ),
        ),
    ]

    out_dir = Path(os.environ.get("HOOKZ_LEAN_SMOKE_DIR", "/tmp/hookz-lean-contract-smoke"))
    out_dir.mkdir(parents=True, exist_ok=True)
    lean_file = out_dir / "BalanceGateGenerated.lean"
    lean_file.write_text(generate_lean(cases))

    cmd = [_lake_binary(), "env", "lean", str(lean_file)]
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode == 0:
        print(f"Lean checked generated cases: {lean_file}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
