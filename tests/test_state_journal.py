"""The state journal — ordered evidence of what a run did to state.

`state_db` shows only the end result. After a rollback, "the hook wrote the
record and then hit the guard" and "the guard fired before anything was
written" leave identical databases; the journal is the record that can tell
them apart. It is evidence, never committed state: a rejected run's writes
stay on it, exactly because that is the ordering proof.
"""

from __future__ import annotations

import pytest

from hookz.runtime import HookRuntime

#: Local create + update, a foreign write, and (by arg) deletes on both
#: scopes — with a trace between the writes and the exits so a raising
#: handler override can model a host failure after a write landed.
#:
#:   arg 0: create, update, foreign create — accept
#:   arg 1: same three writes — rollback (the guard fires after the writes)
#:   arg 2: the three writes, then local delete + foreign delete — accept
SOURCE = """
#include "hookapi.h"

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    uint8_t key[32] = {0x05};
    uint8_t v1[8] = {0x11};
    uint8_t v2[8] = {0x22};
    state_set(SBUF(v1), SBUF(key));
    state_set(SBUF(v2), SBUF(key));

    uint8_t ns[32]  = {0xAA};
    uint8_t acc[20] = {0xBB};
    uint8_t fv[8]   = {0x33};
    state_foreign_set(SBUF(fv), SBUF(key), SBUF(ns), SBUF(acc));

    TRACESTR("wrote");

    if (reserved == 2)
    {
        state_set(0, 0, SBUF(key));
        state_foreign_set(0, 0, SBUF(key), SBUF(ns), SBUF(acc));
    }
    if (reserved == 1)
        return rollback(SBUF("guard fired after the writes"), 9);
    return accept(SBUF("ok"), 8);
}

int64_t cbak(uint32_t ctx)
{
    _g(1, 1);
    uint8_t key[32] = {0x06};
    uint8_t val[8] = {0x66};
    state_set(SBUF(val), SBUF(key));
    return accept(SBUF("cb"), 7);
}
"""

KEY = bytes([0x05]) + b"\x00" * 31
CBAK_KEY = bytes([0x06]) + b"\x00" * 31
FOREIGN_NS = bytes([0xAA]) + b"\x00" * 31
FOREIGN_ACC = bytes([0xBB]) + b"\x00" * 19
V1 = bytes([0x11]) + b"\x00" * 7
V2 = bytes([0x22]) + b"\x00" * 7
FV = bytes([0x33]) + b"\x00" * 7


@pytest.fixture(scope="module")
def wasm(tmp_path_factory):
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    config = load_config()
    if not (config.wasi_sdk / "bin" / "clang").exists():
        pytest.skip("wasi-sdk not found")
    source = tmp_path_factory.mktemp("journal") / "journal.c"
    source.write_text(SOURCE)
    return compile_hook(source, None, config)


class TestWhatIsRecorded:
    def test_creates_updates_and_scopes_in_order(self, wasm):
        rt = HookRuntime()
        result = rt.run(wasm)
        assert result.accepted

        create, update, foreign = result.state_writes
        assert (create.scope, create.key, create.value) == ("local", KEY, V1)
        assert (update.scope, update.key, update.value) == ("local", KEY, V2)
        assert create.account == rt.hook_account
        assert create.namespace == b"\x00" * 32
        assert create.result == 8

        assert foreign.scope == "foreign"
        assert foreign.account == FOREIGN_ACC
        assert foreign.namespace == FOREIGN_NS
        assert (foreign.key, foreign.value) == (KEY, FV)

    def test_deletes_are_recorded_with_value_none(self, wasm):
        result = HookRuntime().run(wasm, arg=2)
        assert result.accepted

        local_delete, foreign_delete = result.state_writes[3:]
        assert (local_delete.scope, local_delete.value) == ("local", None)
        assert local_delete.key == KEY and local_delete.result == 0
        assert (foreign_delete.scope, foreign_delete.value) == (
            "foreign", None)
        assert foreign_delete.account == FOREIGN_ACC

    def test_the_export_is_attributed(self, wasm):
        rt = HookRuntime()
        rt.run(wasm)
        rt.run(wasm, export="cbak", arg=0)

        assert [w.export for w in rt.state_journal] == [
            "hook", "hook", "hook", "cbak",
        ]
        assert rt.state_journal[-1].key == CBAK_KEY


class TestEvidenceNotCommittedState:
    def test_a_rejected_runs_writes_stay_on_the_record(self, wasm):
        """The reason the journal exists: the guard fired *after* the
        writes, and the journal is what proves that ordering."""
        rt = HookRuntime()
        result = rt.run(wasm, arg=1)
        assert result.rejected

        assert [w.value for w in result.state_writes] == [V1, V2, FV]
        assert len(rt.state_journal) == 3

    def test_journaling_changes_no_commit_semantics(self, wasm):
        """Phase 2 is additive: the databases behave exactly as before,
        including keeping a rejected run's writes."""
        rt = HookRuntime()
        rt.run(wasm, arg=1)
        assert rt.state_db[KEY] == V2
        assert rt._foreign_state_db[(FOREIGN_ACC, FOREIGN_NS, KEY)] == FV

    def test_a_host_error_after_a_write_keeps_the_evidence(self, wasm):
        """The write landed, then the host blew up — the journal must still
        say the write happened."""
        rt = HookRuntime()

        def explode(*_args):
            raise RuntimeError("host failure after the writes")

        rt.handlers["trace"] = explode
        result = rt.run(wasm)

        assert result.error is not None
        assert [w.value for w in result.state_writes] == [V1, V2, FV]


class TestPerRunSlices:
    def test_the_journal_is_durable_and_slices_are_not(self, wasm):
        rt = HookRuntime()
        first = rt.run(wasm)
        second = rt.run(wasm, arg=2)

        assert len(first.state_writes) == 3
        assert len(second.state_writes) == 5
        assert len(rt.state_journal) == 8
        assert rt.state_journal[:3] == first.state_writes

    def test_an_overridden_handler_bypasses_the_journal(self, wasm):
        """Documented, not incidental: a test's own state_set override
        replaces the builtin, so nothing journals — an interceptor that
        wants its refusals on the record adds them itself (Phase 4)."""
        rt = HookRuntime()
        rt.handlers["state_set"] = lambda *_args: 8
        result = rt.run(wasm)

        assert result.accepted
        assert [w.scope for w in result.state_writes] == ["foreign"], (
            "only the un-overridden builtin should journal")
