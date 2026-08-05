"""`run(export=, arg=)` — one execution lifecycle for every exported function.

`hook` and `cbak` are both exports of the same module; before this, calling
`cbak` meant reconstructing `run()` by hand around a different export name,
and the copies of that reconstruction drifted (coverage merged differently,
per-run fields reset differently, `_has_cbak` forgotten). These tests pin the
one lifecycle: which export runs, what a run resets, and what it deliberately
carries across runs on one runtime.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hookz.runtime import HookResult, HookRuntime
from hookz.handlers.dev import Checkpoint

#: Two exports, distinguishable by exit code and state key. `arg` is echoed
#: through the accept code on the cbak side so the test can prove it arrived.
SOURCE = """
#include "hookapi.h"

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    uint8_t key[32] = {0x01};
    uint8_t val[8] = {0x11};
    state_set(SBUF(val), SBUF(key));
    TRACESTR("hook ran");
    return accept(SBUF("hook side"), 7);
}

int64_t cbak(uint32_t ctx)
{
    _g(1, 1);
    uint8_t key[32] = {0x02};
    uint8_t val[8] = {0x22};
    state_set(SBUF(val), SBUF(key));
    TRACESTR("cbak ran");
    return accept(SBUF("cbak side"), 100 + ctx);
}
"""


@pytest.fixture(scope="module")
def wasm(tmp_path_factory):
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    config = load_config()
    if not (config.wasi_sdk / "bin" / "clang").exists():
        pytest.skip("wasi-sdk not found")
    source = tmp_path_factory.mktemp("two-exports") / "two_exports.c"
    source.write_text(SOURCE)
    return compile_hook(source, None, config)


class TestExportSelection:
    def test_the_default_export_is_hook(self, wasm):
        result = HookRuntime().run(wasm)
        assert result.accepted
        assert result.return_msg_str == "hook side"
        assert result.return_code == 7

    def test_cbak_runs_and_receives_its_argument(self, wasm):
        result = HookRuntime().run(wasm, export="cbak", arg=1)
        assert result.accepted
        assert result.return_msg_str == "cbak side"
        assert result.return_code == 101, "arg did not reach the export"

    def test_a_missing_export_is_a_loud_error(self, wasm):
        rt = HookRuntime()
        with pytest.raises(RuntimeError, match="does not export 'settle'"):
            rt.run(wasm, export="settle")
        assert rt._store is None and rt._memory is None, (
            "the failed run left engine state attached to the runtime")

    def test_has_cbak_is_derived_on_a_cbak_run_too(self, wasm):
        """Emission validation reads `_has_cbak`; a lifecycle that only set it
        for `hook` runs would judge a callback's own emits against a stale or
        never-set value."""
        rt = HookRuntime()
        rt.run(wasm, export="cbak", arg=0)
        assert rt._has_cbak is True


class TestFieldLifecycle:
    """The classification in `run()`'s docstring, held to with one runtime."""

    def test_per_run_evidence_is_fresh_each_run(self, wasm):
        rt = HookRuntime()
        first = rt.run(wasm)
        assert [t.tag for t in rt.traces] == ['"hook ran"']
        assert any(c.name == "state_set" for c in first.call_log)

        second = rt.run(wasm, export="cbak", arg=1)
        assert [t.tag for t in rt.traces] == ['"cbak ran"'], (
            "traces leaked across runs")
        assert second.call_log is not first.call_log
        # each source traces exactly once — a leaked first-run call log would
        # show two traces, and a missing reset would show the first run's
        assert sum(c.name == "trace" for c in second.call_log) == 1
        assert sum(c.name == "trace" for c in first.call_log) == 1

    def test_state_is_durable_across_runs(self, wasm):
        """Multi-delivery tests read what an earlier run committed — the
        runtime is the ledger between transactions, so state carries."""
        rt = HookRuntime()
        rt.run(wasm)
        key_hook = bytes([0x01]) + b"\x00" * 31
        assert rt.state_db[key_hook] == bytes([0x11]) + b"\x00" * 7

        rt.run(wasm, export="cbak", arg=0)
        key_cbak = bytes([0x02]) + b"\x00" * 31
        assert rt.state_db[key_hook] == bytes([0x11]) + b"\x00" * 7, (
            "an earlier run's state write did not survive the next run")
        assert rt.state_db[key_cbak] == bytes([0x22]) + b"\x00" * 7

    def test_params_and_handlers_are_durable(self, wasm):
        rt = HookRuntime()
        rt.params["CFG"] = b"\x01"
        seen: list[str] = []
        original = rt.handlers.get("trace")

        rt.run(wasm)
        rt.run(wasm, export="cbak", arg=0)
        assert rt.params[b"CFG"] == b"\x01"
        assert rt.handlers.get("trace") is original


#: Emits one transaction whose first byte is `arg + 1`, then accepts unless
#: `arg == 1`. Lets one runtime host every accept/reject sequence with
#: distinguishable emissions.
EMITTING_SOURCE = """
#include "hookapi.h"

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    etxn_reserve(1);
    uint8_t tx[16] = { (uint8_t)(reserved + 1) };
    uint8_t hsh[32];
    emit(SBUF(hsh), SBUF(tx));
    if (reserved == 1)
        return rollback(SBUF("refused"), 21);
    return accept(SBUF("done"), 20);
}
"""


@pytest.fixture(scope="module")
def emitting_wasm(tmp_path_factory):
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    config = load_config()
    if not (config.wasi_sdk / "bin" / "clang").exists():
        pytest.skip("wasi-sdk not found")
    source = tmp_path_factory.mktemp("emitting") / "emitting.c"
    source.write_text(EMITTING_SOURCE)
    return compile_hook(source, None, config)


def _tx(arg: int) -> bytes:
    return bytes([arg + 1]) + b"\x00" * 15


class TestEmissionBoundaryAcrossRuns:
    """One runtime, many transactions: emissions are per-run pending, and
    only an *accepting* run's join the durable history. A later rejection
    must not be able to report, reclassify, or clear an earlier run's
    accepted emissions."""

    def _rt(self) -> HookRuntime:
        rt = HookRuntime()
        rt.validate_emissions = False   # the 16-byte stub is not a real txn
        return rt

    def test_accept_then_accept_accumulates_history_per_run(
        self, emitting_wasm
    ):
        rt = self._rt()
        first = rt.run(emitting_wasm, arg=0)
        second = rt.run(emitting_wasm, arg=2)
        assert first.accepted and second.accepted

        assert rt.emitted_txns == [_tx(0), _tx(2)]
        assert first.emitted_txns == [_tx(0)]
        assert second.emitted_txns == [_tx(2)], (
            "a result reported another run's emissions")

    def test_the_second_run_gets_its_own_reservation(self, emitting_wasm):
        """etxn_reserve is once per hook execution, and the emit cap counts
        this run's slice — a durable reservation would refuse every emit
        after the first transaction."""
        rt = self._rt()
        rt.run(emitting_wasm, arg=0)
        second = rt.run(emitting_wasm, arg=2)

        reserves = [c.result for c in second.call_log
                    if c.name == "etxn_reserve"]
        emits = [c.result for c in second.call_log if c.name == "emit"]
        assert reserves == [1], "the first run's reservation leaked"
        assert emits == [32], "the emit cap counted the durable history"

    def test_a_later_rejection_cannot_consume_accepted_history(
        self, emitting_wasm
    ):
        rt = self._rt()
        rt.run(emitting_wasm, arg=0)
        rejected = rt.run(emitting_wasm, arg=1)
        assert rejected.rejected

        assert rt.emitted_txns == [_tx(0)], (
            "a rejecting run withdrew an earlier run's accepted emissions")
        assert rejected.emitted_txns == []
        assert rejected.attempted_emissions == [_tx(1)]
        assert rt.attempted_emissions == [_tx(1)], (
            "attempted must be this run's emissions only")

    def test_reject_then_accept_leaves_only_the_accepted_run(
        self, emitting_wasm
    ):
        rt = self._rt()
        rt.run(emitting_wasm, arg=1)
        assert rt.emitted_txns == []
        accepted = rt.run(emitting_wasm, arg=0)

        assert accepted.accepted
        assert rt.emitted_txns == [_tx(0)]
        assert rt.attempted_emissions == [], (
            "a stale attempted list survived into the accepting run")
        assert accepted.attempted_emissions == []

    def test_emission_diagnostics_are_per_run(self, emitting_wasm):
        """A validation refusal recorded by one run must not still be on the
        runtime when the next run's evidence is read."""
        rt = HookRuntime()          # validation ON — the stub txn is refused
        first = rt.run(emitting_wasm, arg=0)
        assert rt.emission_rejections, "the stub unexpectedly validated"
        assert first.accepted       # the hook ignores emit()'s return code

        rt.validate_emissions = False
        rt.run(emitting_wasm, arg=2)
        assert rt.emission_rejections == [], (
            "an earlier run's rejection diagnostics leaked")


class TestRequireCheckpoint:
    def _result(self, **kw) -> HookResult:
        result = HookResult(**kw)
        return result

    def test_a_present_checkpoint_is_returned(self):
        result = self._result(checkpoints=[Checkpoint(tag="priced")])
        assert result.require_checkpoint("priced").tag == "priced"

    def test_a_missing_checkpoint_names_the_exit_taken(self):
        result = self._result(
            rejected=True, return_msg=b"guard fired\x00", return_code=42,
            checkpoints=[Checkpoint(tag="other")],
        )
        with pytest.raises(AssertionError) as e:
            result.require_checkpoint("priced")
        message = str(e.value)
        assert "'priced' was never reached" in message
        assert "42" in message and "guard fired" in message
        assert "['other']" in message

    def test_no_checkpoints_at_all_points_at_instrumentation(self):
        with pytest.raises(AssertionError, match="compile_hook_dev"):
            self._result().require_checkpoint("priced")
