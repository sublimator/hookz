"""Runtime semantics that are not any one host function's behaviour."""

from __future__ import annotations

import pytest


class TestEmissionsFollowTheHooksOutcome:
    """A rolled-back hook emits nothing.

    xahaud holds emitted transactions on the hook result and applies them only
    when it succeeded — `finalizeHookResult(hookResult, ctx_,
    isTesSuccess(result))` (xahaud:src/xrpld/app/tx/detail/Transactor.cpp:2026)
    drains the queue under `if (doEmit)`. The field itself is commented "etx
    stored here until accept/rollback"
    (xahaud:src/xrpld/app/hook/applyHook.h:149).

    Reporting them regardless lets a test assert that a payout happened on a
    run where the hook refused — the payout is the observable most worth
    getting right, and a rollback is the most common way a hook declines one.
    """

    SOURCE = """
        #include "hookapi.h"
        int64_t hook(uint32_t r) {
            etxn_reserve(1);
            uint8_t txn[64];
            CLEARBUF(txn);
            uint8_t h[32];
            emit(SBUF(h), SBUF(txn));
            %s(SBUF("done"), __LINE__);
            _g(1,1);
            return 0;
        }
    """

    @pytest.fixture
    def run(self, tmp_path):
        from hookz.compiler import compile_hook
        from hookz.runtime import HookRuntime

        def _run(verb: str):
            src = tmp_path / f"{verb}.c"
            src.write_text(self.SOURCE % verb)
            rt = HookRuntime()
            rt.hook_account = b"\xa0" * 20
            rt.otxn_account = b"\x01" * 20
            # the blob is not a transaction; this test is about what becomes of
            # the queue, not about what was put in it
            rt.validate_emissions = False
            return rt.run(compile_hook(src)), rt

        return _run

    def test_an_accepted_emit_is_reported(self, run):
        result, rt = run("accept")

        assert result.accepted, result.return_msg_str
        assert len(rt.emitted_txns) == 1
        assert rt.attempted_emissions == []

    def test_a_rolled_back_emit_is_not(self, run):
        result, rt = run("rollback")

        assert result.rejected
        assert rt.emitted_txns == [], "the ledger would never have seen it"
        assert result.emitted_txns == []

    def test_but_the_attempt_is_still_visible(self, run):
        """"Tried to pay, then refused" and "never reached the emit" are
        different statements, and a test may need to tell them apart."""
        result, rt = run("rollback")

        assert len(rt.attempted_emissions) == 1
        assert result.attempted_emissions == rt.attempted_emissions
