"""Typed fault injection — refuse host calls, and keep the receipts.

**This is fault injection, not a model of anything.** Nothing here reproduces
a condition under which the network would refuse a particular call; it
substitutes the return code so a test can ask what the hook does with it.
What it emulates is only the *contract*: a host function hands back a
negative number and a hook that does not check it carries on regardless.

The codes are real, though, and worth choosing accurately. `state_set` can
come back `RESERVE_INSUFFICIENT` — xahaud routes both a write and a delete
through the same reserve accounting
(xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1902-1916,
xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2733-2777) — or
`TOO_MANY_STATE_MODIFICATIONS` once a hook has changed more entries than its
budget allows. `emit` returns `PREREQUISITE_NOT_MET` without an
`etxn_reserve` (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:505),
`TOO_MANY_EMITTED_TXN` once the reserved count is used up (…:508), and
`EMISSION_FAILURE` when the blob fails a rule or the transactor's preflight
(…:511).

So a test built on this module proves the hook *checks the return value* —
a real property worth having — but not that the call at that site can
actually fail. Where the second thing is wanted, drive the rule instead:
reach the refusal through the hook's own arithmetic, with nothing injected.
And every fault test deserves its paired control: the same run with nothing
refused, green, proving the injection is what changed the outcome and that
it actually reached the host boundary.

The injectors wrap the builtin handlers — they never re-implement their
validation, so a call the host itself would refuse (a bad key width, an
oversized value, an emit with no reservation, an exhausted reserved count,
a short output buffer, a transaction failing the emission rules) receives
the host's own answer *before* any fault is considered, exactly as on
chain, and never appears in the fault log. The selector is only ever asked
about a call that would otherwise have succeeded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi


@dataclass
class FaultCall:
    """One host call as the fault layer saw it.

    `refused` says whether the injector substituted `result`; either way
    `result` is what the hook was handed. For `state_set`, `key`/`value`
    are decoded (`value is None` marks a delete); for `emit`, `blob` is the
    serialized transaction. `index` is the call's 0-based position in its
    log, and `args` carries the raw wasm arguments for generic refusals.
    """
    name: str
    index: int
    key: bytes | None = None
    value: bytes | None = None
    blob: bytes | None = None
    args: tuple = field(default_factory=tuple)
    refused: bool = False
    result: int = 0

    @property
    def is_delete(self) -> bool:
        return self.name == "state_set" and self.value is None


def every(call: FaultCall) -> bool:
    """`when=` predicate: every admitted call is refused.

    "Admitted" is load-bearing — the builtin's own refusals still answer
    first, so this is "the host would have accepted it, the network said
    no", not a blanket short-circuit.
    """
    return True


def deletes(call: FaultCall) -> bool:
    """`when=` predicate: every state delete is refused.

    Checks the call's name, not just its value — emit and generic records
    also carry `value=None`, and a predicate that matched them would refuse
    every emit while claiming to select deletes.
    """
    return call.is_delete


def nth(n: int) -> Callable[[FaultCall], bool]:
    """`when=` predicate: the call at 0-based position `n` is refused."""
    return lambda call: call.index == n


def refuse_state_set(rt: HookRuntime,
                     when: Callable[[FaultCall], bool] | None = None,
                     code: int = hookapi.RESERVE_INSUFFICIENT
                     ) -> list[FaultCall]:
    """Log every `state_set`, refusing the ones `when` selects.

    The mock's builtin `state_set` always succeeds, which quietly makes
    every unchecked write in a hook look safe. On chain it is not — see the
    module docstring for the codes — and a hook that discards the return
    value cannot tell.

    `when` receives the decoded `FaultCall` (key, value, index; `value is
    None` marks a delete — both spellings go through the same accounting
    upstream, so both are refusable). Refused calls leave state untouched
    and return `code`; they also land on the runtime's state journal with
    the refusal as their result, so "the hook attempted the delete and
    ignored the answer" is provable from one record. `when=None` only logs.

    Returns the live log; it fills in as the hook runs.
    """
    from hookz.handlers.state import _journal, _state_set_error
    from hookz.handlers.state import state_set as builtin

    log: list[FaultCall] = []

    def handler(read_ptr, read_len, kread_ptr, kread_len):
        err = _state_set_error(rt, read_ptr, read_len, kread_ptr, kread_len)
        if err is not None:
            return err
        key = rt._read_memory(kread_ptr, kread_len)
        is_delete = read_ptr == 0 and read_len == 0
        val = None if is_delete else rt._read_memory(read_ptr, read_len)
        call = FaultCall(name="state_set", index=len(log), key=key, value=val)
        if when is not None and when(call):
            call.refused = True
            call.result = code
            log.append(call)
            _journal(rt, "local", rt.hook_account, rt.hook_namespace,
                     key, val, code)
            return code
        call.result = builtin(rt, read_ptr, read_len, kread_ptr, kread_len)
        log.append(call)
        return call.result

    rt.handlers["state_set"] = handler
    return log


def refuse_emit(rt: HookRuntime,
                when: Callable[[FaultCall], bool] | None = None,
                code: int = hookapi.EMISSION_FAILURE) -> list[FaultCall]:
    """Log every `emit`, refusing the ones `when` selects.

    `when` receives the `FaultCall` with the serialized transaction as
    `blob` and its 0-based position in this log as `index`. A refused emit
    returns `code` with nothing appended to the emission queue.
    `when=None` only logs.

    The builtin's whole preflight runs first, in the pinned host's order —
    buffer bounds, output width, reservation, reserved count, the emission
    rules — so a call the ordinary runtime would refuse gets the ordinary
    answer (OUT_OF_BOUNDS, TOO_SMALL, PREREQUISITE_NOT_MET,
    TOO_MANY_EMITTED_TXN, EMISSION_FAILURE with its diagnostics), never
    the injected code, and never appears in the log. The selector is only
    ever asked about an emit that would otherwise have succeeded.

    Returns the live log; it fills in as the hook runs.
    """
    from hookz.handlers.emit import _emit_commit, _emit_preflight

    log: list[FaultCall] = []

    def handler(hash_ptr, hash_len, txn_ptr, txn_len):
        err, blob = _emit_preflight(rt, hash_ptr, hash_len, txn_ptr, txn_len)
        if err is not None:
            return err
        call = FaultCall(name="emit", index=len(log), blob=blob)
        if when is not None and when(call):
            call.refused = True
            call.result = code
            log.append(call)
            return code
        call.result = _emit_commit(rt, hash_ptr, hash_len, blob)
        log.append(call)
        return call.result

    rt.handlers["emit"] = handler
    return log


#: Hosts with a typed injector; the blunt form refuses to touch them,
#: because it would bypass exactly the admission ordering, diagnostics,
#: and decoded receipts the typed wrapper exists to preserve.
_TYPED_HOSTS = {"state_set": "refuse_state_set", "emit": "refuse_emit"}


def _reject_typed(name: str) -> None:
    typed = _TYPED_HOSTS.get(name)
    if typed is not None:
        raise ValueError(
            f"refuse_host cannot inject into {name!r}: use faults.{typed} "
            f"(with when=faults.every for an unconditional refusal) — the "
            f"blunt form would bypass the host's own admission checks, its "
            f"diagnostics, and the decoded receipts")


def refuse_host(rt: HookRuntime, name: str, code: int) -> list[FaultCall]:
    """Refuse every call to host function `name` with `code`.

    The bluntest injector: no decoding, no delegation — the named function
    simply answers `code`, and the log records each call's raw arguments.
    Hosts with a typed injector (`state_set`, `emit`) are refused here on
    purpose; use the typed form, which still runs the host's admission
    checks first.
    """
    _reject_typed(name)
    log: list[FaultCall] = []

    def handler(*args):
        log.append(FaultCall(name=name, index=len(log), args=args,
                             refused=True, result=code))
        return code

    rt.handlers[name] = handler
    return log


def refusing(name: str, code: int) -> Callable[["HookRuntime"], None]:
    """A `setup(rt)` callable for `refuse_host` — the shape suite drivers
    take, so `setup=faults.refusing("etxn_reserve", TOO_SMALL)` is a
    drop-in for the local one-off factories it replaces. Typed hosts are
    rejected eagerly; see `refusing_emit` for the emit boundary."""
    _reject_typed(name)

    def setup(rt: HookRuntime) -> None:
        refuse_host(rt, name, code)
    return setup


def refusing_emit(code: int = hookapi.EMISSION_FAILURE) -> Callable[["HookRuntime"], None]:
    """A `setup(rt)` callable that refuses every *admitted* emit with `code`.

    `refusing`'s typed counterpart for the emit boundary: the preflight
    still answers first (reservation, count, width, the emission rules,
    with their diagnostics), and only an emit the host would have accepted
    comes back `code`. The log is discarded — a driver that needs receipts
    calls `refuse_emit` directly.
    """
    def setup(rt: HookRuntime) -> None:
        refuse_emit(rt, when=every, code=code)
    return setup
