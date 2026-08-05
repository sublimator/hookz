"""`hookz.testing.faults` — refusals with receipts.

Every fault test here keeps its paired control: the same run with nothing
refused, green, proving the injection is what changed the outcome and that
it actually reached the host boundary.
"""

from __future__ import annotations

import re

import pytest

from hookz import hookapi
from hookz.runtime import HookRuntime
from hookz.testing import faults

#: arg 0 — create K1, create K2, delete K3, then record the three return
#: codes under RK1 (a key no fault predicate here ever targets).
#: arg 1 — reserve two emissions, emit twice, record the codes under RK2.
#: arg 2 — one state_set with an illegally wide key; the accept code carries
#: its result, so the probe needs no working state_set to report.
SOURCE = """
#include "hookapi.h"

int64_t cbak(uint32_t ctx)
{
    _g(1, 1);
    return accept(SBUF("cb"), 0);
}

int64_t hook(uint32_t reserved)
{
    _g(1, 1);
    uint8_t rk[32] = {0xF0};
    uint8_t out[24];

    if (reserved == 0)
    {
        uint8_t k1[32] = {0x01};
        uint8_t k2[32] = {0x02};
        uint8_t k3[32] = {0x03};
        uint8_t v[4] = {0xAA};
        int64_t r1 = state_set(SBUF(v), SBUF(k1));
        int64_t r2 = state_set(SBUF(v), SBUF(k2));
        int64_t r3 = state_set(0, 0, SBUF(k3));
        INT64_TO_BUF(out, r1);
        INT64_TO_BUF(out + 8, r2);
        INT64_TO_BUF(out + 16, r3);
        rk[1] = 1;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("writes"), 0);
    }
    if (reserved == 1)
    {
        int64_t rr = etxn_reserve(2);
        uint8_t t1[16] = {0x11};
        uint8_t t2[16] = {0x22};
        uint8_t h[32];
        int64_t e1 = emit(SBUF(h), SBUF(t1));
        int64_t e2 = emit(SBUF(h), SBUF(t2));
        INT64_TO_BUF(out, rr);
        INT64_TO_BUF(out + 8, e1);
        INT64_TO_BUF(out + 16, e2);
        rk[1] = 2;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("emits"), 0);
    }
    if (reserved == 2)
    {
        uint8_t wide[33] = {0x04};
        uint8_t v[4] = {0xBB};
        int64_t rc = state_set(SBUF(v), wide, 33);
        return accept(SBUF("badkey"), rc);
    }
    if (reserved == 3)
    {
        int64_t rr = etxn_reserve(1);
        uint8_t t1[16] = {0x31};
        uint8_t h[32];
        int64_t e1 = emit(h, 31, SBUF(t1));
        int64_t e2 = emit(SBUF(h), SBUF(t1));
        int64_t e3 = emit(SBUF(h), SBUF(t1));
        uint8_t wide[32];
        INT64_TO_BUF(wide, rr);
        INT64_TO_BUF(wide + 8, e1);
        INT64_TO_BUF(wide + 16, e2);
        INT64_TO_BUF(wide + 24, e3);
        rk[1] = 3;
        state_set(SBUF(wide), SBUF(rk));
        return accept(SBUF("preflight"), 0);
    }
    if (reserved == 4)
    {
        uint8_t t1[16] = {0x41};
        uint8_t h[32];
        int64_t e1 = emit(h, 31, SBUF(t1));
        int64_t e2 = emit(SBUF(h), 0x7FFFFF00u, 16);
        uint8_t out[16];
        INT64_TO_BUF(out, e1);
        INT64_TO_BUF(out + 8, e2);
        rk[1] = 4;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("wrapper"), 0);
    }
    if (reserved == 5)
    {
        uint8_t k1[32] = {0x05};
        uint8_t v[4] = {0xCC};
        uint8_t wide[33] = {0x06};
        int64_t r1 = state_set(0x7FFFFF00u, 4, SBUF(k1));
        int64_t r2 = state_set(0x7FFFFF00u, 4, wide, 33);
        int64_t r3 = state_set(SBUF(v), 0x7FFFFF00u, 32);
        uint8_t out[24];
        INT64_TO_BUF(out, r1);
        INT64_TO_BUF(out + 8, r2);
        INT64_TO_BUF(out + 16, r3);
        rk[1] = 5;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("bounds"), r2);
    }
    if (reserved == 7)
    {
        int64_t v = float_set(-6, 1500000);
        uint8_t out[8];
        INT64_TO_BUF(out, v);
        rk[1] = 7;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("xfl"), 0);
    }
    if (reserved == 9)
    {
        /* Both delete spellings: zero/zero, and a live pointer with a zero
           length. The host slices an empty blob either way. */
        uint8_t k1[32] = {0x0A};
        uint8_t k2[32] = {0x0B};
        uint8_t v[4] = {0xEE};
        state_set(SBUF(v), SBUF(k1));
        state_set(SBUF(v), SBUF(k2));
        int64_t d1 = state_set(0, 0, SBUF(k1));
        int64_t d2 = state_set(v, 0, SBUF(k2));
        uint8_t out[16];
        INT64_TO_BUF(out, d1);
        INT64_TO_BUF(out + 8, d2);
        rk[1] = 9;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("deletes"), 0);
    }
    if (reserved == 8)
    {
        /* one emission reserved, two attempts: the second is refused by the
           count unless the first never made it into the queue. */
        etxn_reserve(1);
        uint8_t h[32];
        uint8_t t1[16] = {0x81};
        uint8_t t2[16] = {0x82};
        int64_t e1 = emit(SBUF(h), SBUF(t1));
        int64_t e2 = emit(SBUF(h), SBUF(t2));
        uint8_t out[16];
        INT64_TO_BUF(out, e1);
        INT64_TO_BUF(out + 8, e2);
        rk[1] = 8;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("reserve"), 0);
    }
    if (reserved == 6)
    {
        etxn_reserve(1);
        uint8_t h[32];
        uint8_t t[16] = {0x61};
        uint8_t k1[32] = {0x07};
        int64_t e1 = emit(SBUF(h), 0xFFFFFFFFu, 16);
        int64_t e2 = emit(SBUF(h), t, 0xFFFFFFFFu);
        int64_t s1 = state_set(0x80000000u, 4, SBUF(k1));
        int64_t s2 = state_set(SBUF(k1), 0xFFFFFFFFu, 32);
        uint8_t out[32];
        INT64_TO_BUF(out, e1);
        INT64_TO_BUF(out + 8, e2);
        INT64_TO_BUF(out + 16, s1);
        INT64_TO_BUF(out + 24, s2);
        rk[1] = 6;
        state_set(SBUF(out), SBUF(rk));
        return accept(SBUF("highbit"), 0);
    }
    return accept(SBUF("noop"), 0);
}
"""

K1 = bytes([0x01]) + b"\x00" * 31
K2 = bytes([0x02]) + b"\x00" * 31
K3 = bytes([0x03]) + b"\x00" * 31
RK1 = bytes([0xF0, 0x01]) + b"\x00" * 30
RK2 = bytes([0xF0, 0x02]) + b"\x00" * 30
RK3 = bytes([0xF0, 0x03]) + b"\x00" * 30
RK4 = bytes([0xF0, 0x04]) + b"\x00" * 30
RK5 = bytes([0xF0, 0x05]) + b"\x00" * 30
RK6 = bytes([0xF0, 0x06]) + b"\x00" * 30
RK7 = bytes([0xF0, 0x07]) + b"\x00" * 30
RK8 = bytes([0xF0, 0x08]) + b"\x00" * 30
RK9 = bytes([0xF0, 0x09]) + b"\x00" * 30
DK1 = bytes([0x0A]) + b"\x00" * 31
DK2 = bytes([0x0B]) + b"\x00" * 31
DV = bytes([0xEE]) + b"\x00" * 3
V = bytes([0xAA]) + b"\x00" * 3
T1 = bytes([0x11]) + b"\x00" * 15
T2 = bytes([0x22]) + b"\x00" * 15


def i64buf(value: int) -> bytes:
    return (value & (2**64 - 1)).to_bytes(8, "big")


def codes(record: bytes) -> list[int]:
    """The int64s the probe packed into a result record."""
    return [
        int.from_bytes(record[i:i + 8], "big", signed=False)
        - (1 << 64 if record[i] & 0x80 else 0)
        for i in range(0, len(record), 8)
    ]


@pytest.fixture(scope="module")
def wasm(tmp_path_factory):
    from hookz.compiler import compile_hook
    from hookz.config import load_config

    config = load_config()
    if not (config.wasi_sdk / "bin" / "clang").exists():
        pytest.skip("wasi-sdk not found")
    source = tmp_path_factory.mktemp("faults") / "faults_probe.c"
    source.write_text(SOURCE)
    return compile_hook(source, None, config)


def emit_rt() -> HookRuntime:
    rt = HookRuntime()
    rt.validate_emissions = False  # the probe's blobs carry no EmitDetails
    return rt


class TestRefuseStateSet:
    def test_control_nothing_refused(self, wasm):
        rt = HookRuntime()
        rt.state_db[K3] = b"doomed"
        log = faults.refuse_state_set(rt)
        rt.run(wasm)

        assert [c.refused for c in log] == [False] * 4
        assert rt.state_db[K1] == V and rt.state_db[K2] == V
        assert K3 not in rt.state_db
        assert codes(rt.state_db[RK1]) == [4, 4, 0]

    def test_a_selected_write_is_refused(self, wasm):
        rt = HookRuntime()
        log = faults.refuse_state_set(rt, when=lambda c: c.key == K2)
        rt.run(wasm)

        assert rt.state_db[K1] == V
        assert K2 not in rt.state_db
        refused = [c for c in log if c.refused]
        assert [(c.key, c.value, c.result) for c in refused] == [
            (K2, V, hookapi.RESERVE_INSUFFICIENT)]
        # The hook was handed the code — whether it looked is its problem.
        assert codes(rt.state_db[RK1])[1] == hookapi.RESERVE_INSUFFICIENT

    def test_a_refused_delete_lands_on_the_journal(self, wasm):
        """The receipt the module exists for: the hook attempted the
        delete, was told no, and what it did next is on the record."""
        rt = HookRuntime()
        rt.state_db[K3] = b"survives"
        faults.refuse_state_set(rt, when=faults.deletes,
                                code=hookapi.TOO_MANY_STATE_MODIFICATIONS)
        result = rt.run(wasm)

        assert rt.state_db[K3] == b"survives"
        attempt = [w for w in result.state_writes if w.key == K3]
        assert [(w.value, w.result) for w in attempt] == [
            (None, hookapi.TOO_MANY_STATE_MODIFICATIONS)]
        assert codes(rt.state_db[RK1])[2] == (
            hookapi.TOO_MANY_STATE_MODIFICATIONS)

    def test_validation_precedes_any_fault(self, wasm):
        """A malformed call is refused by the host's own checks, with the
        host's own code — the fault layer never sees it."""
        rt = HookRuntime()
        log = faults.refuse_state_set(rt, when=lambda c: True,
                                      code=hookapi.RESERVE_INSUFFICIENT)
        result = rt.run(wasm, arg=2)

        assert result.return_code == hookapi.TOO_BIG
        assert log == []

    def test_bounds_precede_width_and_any_fault(self, wasm):
        """arg 5: an out-of-bounds value pointer answers OUT_OF_BOUNDS even
        alongside an illegally wide key and under a match-all selector —
        the wrapper's bounds come first (the state_set wrapper delegates
        to state_foreign_set's, applyHook.cpp:1293-1314). Only the probe's
        own valid result write ever reaches the selector."""
        rt = HookRuntime()
        log = faults.refuse_state_set(rt, when=lambda c: True)
        result = rt.run(wasm, arg=5)

        assert result.return_code == hookapi.OUT_OF_BOUNDS
        assert [(c.key, c.refused) for c in log] == [(RK5, True)]

    def test_bounds_precedence_holds_without_any_fault(self, wasm):
        """Paired control: the builtin alone resolves all three the same
        way — OOB value, OOB value + wide key, OOB key."""
        rt = HookRuntime()
        rt.run(wasm, arg=5)
        assert codes(rt.state_db[RK5]) == [hookapi.OUT_OF_BOUNDS] * 3

    def test_log_only_when_none(self, wasm):
        rt = HookRuntime()
        log = faults.refuse_state_set(rt)
        rt.run(wasm)
        assert [(c.key, c.is_delete) for c in log[:3]] == [
            (K1, False), (K2, False), (K3, True)]
        assert [c.index for c in log] == [0, 1, 2, 3]


class TestRefuseEmit:
    def test_control_nothing_refused(self, wasm):
        rt = emit_rt()
        log = faults.refuse_emit(rt)
        result = rt.run(wasm, arg=1)

        assert result.emitted_txns == [T1, T2]
        assert [(c.blob, c.refused) for c in log] == [
            (T1, False), (T2, False)]

    def test_the_selected_emit_is_refused(self, wasm):
        rt = emit_rt()
        log = faults.refuse_emit(rt, when=faults.nth(1))
        result = rt.run(wasm, arg=1)

        assert result.emitted_txns == [T1]
        assert [(c.blob, c.refused) for c in log] == [
            (T1, False), (T2, True)]
        assert codes(rt.state_db[RK2]) == [2, 32, hookapi.EMISSION_FAILURE]

    def test_the_code_is_the_callers_choice(self, wasm):
        rt = emit_rt()
        faults.refuse_emit(rt, when=faults.nth(0),
                           code=hookapi.TOO_MANY_EMITTED_TXN)
        rt.run(wasm, arg=1)
        assert codes(rt.state_db[RK2])[1] == hookapi.TOO_MANY_EMITTED_TXN


class TestEmitPreflightBeatsTheSelector:
    """A call the host itself would refuse gets the host's answer, never the
    injected code, and never appears in the log — the selector is only ever
    asked about an emit that would otherwise have succeeded."""

    def test_no_reservation_answers_prerequisite_not_met(self, wasm):
        rt = emit_rt()
        faults.refuse_host(rt, "etxn_reserve", hookapi.TOO_SMALL)
        log = faults.refuse_emit(rt, when=lambda c: True,
                                 code=hookapi.INTERNAL_ERROR)
        rt.run(wasm, arg=1)

        assert codes(rt.state_db[RK2])[1:] == [
            hookapi.PREREQUISITE_NOT_MET, hookapi.PREREQUISITE_NOT_MET]
        assert log == []

    def test_short_output_and_exhausted_count_answer_first(self, wasm):
        """arg 3: a 31-byte output buffer, one committing emit against a
        reservation of one, then a third emit into the exhausted count."""
        rt = emit_rt()
        log = faults.refuse_emit(rt, when=faults.nth(1),
                                 code=hookapi.INTERNAL_ERROR)
        result = rt.run(wasm, arg=3)

        rr, e1, e2, e3 = codes(rt.state_db[RK3])
        assert rr == 1
        assert e1 == hookapi.TOO_SMALL
        assert e2 == 32
        assert e3 == hookapi.TOO_MANY_EMITTED_TXN
        # Only the committing emit ever reached the selector, so nth(1)
        # never fired and nothing was refused.
        assert [(c.refused, c.result) for c in log] == [(False, 32)]
        assert result.emitted_txns == [bytes([0x31]) + b"\x00" * 15]

    def test_wrapper_checks_precede_reservation(self, wasm):
        """Overlapping failures resolve in the pinned wrapper's order:
        unreserved + short output answers TOO_SMALL, unreserved +
        out-of-bounds transaction answers OUT_OF_BOUNDS — never
        PREREQUISITE_NOT_MET, and never the injected code
        (applyHook.cpp:2662-2669 before HookAPI.cpp:504-508)."""
        rt = emit_rt()
        log = faults.refuse_emit(rt, when=lambda c: True,
                                 code=hookapi.INTERNAL_ERROR)
        rt.run(wasm, arg=4)

        assert codes(rt.state_db[RK4]) == [
            hookapi.TOO_SMALL, hookapi.OUT_OF_BOUNDS]
        assert log == []

    def test_wrapper_precedence_holds_without_any_fault(self, wasm):
        """Paired control: the builtin alone resolves the same way."""
        rt = emit_rt()
        rt.run(wasm, arg=4)
        assert codes(rt.state_db[RK4]) == [
            hookapi.TOO_SMALL, hookapi.OUT_OF_BOUNDS]

    def test_a_selected_but_invalid_emission_keeps_its_diagnostics(self, wasm):
        """With validation on, the probe's bare blobs fail the emission
        rules: EMISSION_FAILURE comes from the rules with its rejection
        recorded, not from the selector."""
        rt = HookRuntime()
        assert rt.validate_emissions
        log = faults.refuse_emit(rt, when=lambda c: True,
                                 code=hookapi.INTERNAL_ERROR)
        rt.run(wasm, arg=1)

        assert codes(rt.state_db[RK2])[1:] == [
            hookapi.EMISSION_FAILURE, hookapi.EMISSION_FAILURE]
        assert len(rt.emission_rejections) == 2
        assert log == []


class TestHighBitArguments:
    """Every hook API parameter is `uint32_t`, but wasmtime hands a Python
    callback the raw i32 bit pattern as a *signed* int — 0xFFFFFFFF arrives
    as -1, which reads as small and in-range everywhere a handler compares
    it against a size. The host compares unsigned
    (xahaud:include/xrpl/hook/Macro.h:230), so these must all refuse."""

    def test_high_bit_pointers_and_lengths_are_out_of_bounds(self, wasm):
        rt = emit_rt()
        rt.run(wasm, arg=6)
        assert codes(rt.state_db[RK6]) == [hookapi.OUT_OF_BOUNDS] * 4

    def test_a_match_all_selector_never_sees_them(self, wasm):
        rt = emit_rt()
        emit_log = faults.refuse_emit(rt, when=faults.every,
                                      code=hookapi.INTERNAL_ERROR)
        state_log = faults.refuse_state_set(rt, when=faults.every,
                                            code=hookapi.INTERNAL_ERROR)
        rt.run(wasm, arg=6)

        assert emit_log == []
        # Only the probe's own valid result write reached the selector —
        # and it is refused too, so the record it carries is the evidence.
        assert [c.key for c in state_log] == [RK6]
        assert codes(state_log[0].value) == [hookapi.OUT_OF_BOUNDS] * 4
        assert RK6 not in rt.state_db

    def test_signed_declarations_keep_their_sign(self):
        """The mask comes from the API declaration, not the wasm signature:
        wasm has one i32, the API has two. `float_set`'s exponent is a
        genuine int32_t and a negative exponent is ordinary — masking it
        turns every small XFL into an astronomical one, which is exactly
        how a blanket-normalization first attempt broke value handling
        across the downstream suite."""
        from hookz.runtime import _unsigned_param_mask

        # (int32_t exponent, int64_t mantissa) — neither is uint32_t.
        assert _unsigned_param_mask("float_set") == (False, False)
        # (uint32_t, uint32_t, int64_t) — the trailing number is signed.
        assert _unsigned_param_mask("trace_num") == (True, True, False)
        # All four of emit's parameters are uint32_t.
        assert _unsigned_param_mask("emit") == (True,) * 4
        # An import the declaration does not describe is left alone.
        assert _unsigned_param_mask("not_a_hook_api_function") is None

    def test_a_negative_xfl_exponent_survives_the_boundary(self, wasm):
        """The behavioural half of the above, through a real hook call."""
        from hookz.xfl import xfl_to_float

        rt = HookRuntime()
        seen = {}

        def capture(exponent, mantissa):
            seen["exponent"] = exponent
            from hookz.handlers.float import float_set as builtin
            return builtin(rt, exponent, mantissa)

        rt.handlers["float_set"] = capture
        rt.run(wasm, arg=7)

        assert seen["exponent"] == -6, "a signed exponent was masked"
        assert xfl_to_float(codes(rt.state_db[RK7])[0]) == pytest.approx(1.5)

    def test_the_predicate_itself_is_unsigned(self, wasm):
        """Called directly, not just through the linker's normalization."""
        from hookz.handlers.core import _not_in_bounds

        rt = HookRuntime()
        captured = {}

        def probe(*_args):
            captured["oob"] = [
                _not_in_bounds(rt, -1, 4),
                _not_in_bounds(rt, 0, -1),
                _not_in_bounds(rt, 0xFFFFFFFF, 4),
            ]
            captured["ok"] = _not_in_bounds(rt, 0, 4)
            return 0

        rt.handlers["etxn_reserve"] = probe
        rt.run(wasm, arg=6)
        assert captured["oob"] == [True, True, True]
        assert captured["ok"] is False


class TestTypedBoundary:
    def test_refuse_host_rejects_typed_hosts(self, wasm):
        for name, typed in (("emit", "refuse_emit"),
                            ("state_set", "refuse_state_set")):
            with pytest.raises(ValueError, match=f"faults.{typed} "):
                faults.refuse_host(HookRuntime(), name, -1)

    def test_refusing_is_pointed_at_the_setup_shaped_counterpart(self, wasm):
        """`refusing` is rejected eagerly, and names a replacement of its own
        shape — `refuse_emit` takes a runtime, so a `setup=`-only driver
        cannot use it, and a message naming it sends the reader nowhere."""
        for name, typed in (("emit", "faults.refusing_emit"),
                            ("state_set", "faults.refusing_state_set")):
            with pytest.raises(ValueError, match=re.escape(typed)) as excinfo:
                faults.refusing(name, -1)
            assert str(excinfo.value).startswith("refusing cannot inject")

    def test_refusing_emit_refuses_only_admitted_calls(self, wasm):
        """arg 3 again: the short output buffer answers with the host's own
        code, and only admitted emits come back with the injected one. The
        third is admitted *because* the second was refused — a refusal is
        never queued, so it leaves its reserved slot free."""
        rt = emit_rt()
        faults.refusing_emit(hookapi.INTERNAL_ERROR)(rt)
        result = rt.run(wasm, arg=3)

        _rr, e1, e2, e3 = codes(rt.state_db[RK3])
        assert e1 == hookapi.TOO_SMALL
        assert e2 == hookapi.INTERNAL_ERROR
        assert e3 == hookapi.INTERNAL_ERROR
        assert result.emitted_txns == []

    def test_a_refused_emit_frees_its_reserved_slot(self, wasm):
        """The paired control for the sentence above, stated as a contrast:
        with one emission reserved, the unfaulted run refuses the second
        emit outright, while refusing the first admits and commits it."""
        rt = emit_rt()
        rt.run(wasm, arg=8)
        assert codes(rt.state_db[RK8]) == [32, hookapi.TOO_MANY_EMITTED_TXN]
        assert len(rt.emitted_txns) == 1

        faulted = emit_rt()
        log = faults.refuse_emit(faulted, when=faults.nth(0),
                                 code=hookapi.INTERNAL_ERROR)
        faulted.run(wasm, arg=8)
        assert codes(faulted.state_db[RK8]) == [hookapi.INTERNAL_ERROR, 32]
        assert [c.refused for c in log] == [True, False]
        assert len(faulted.emitted_txns) == 1

    def test_refusing_state_set_refuses_only_admitted_writes(self, wasm):
        """arg 2's illegally wide key still answers TOO_BIG; the setup-shaped
        typed injector never sees it."""
        rt = HookRuntime()
        faults.refusing_state_set(hookapi.TOO_MANY_STATE_MODIFICATIONS)(rt)
        result = rt.run(wasm, arg=2)

        assert result.return_code == hookapi.TOO_BIG
        assert rt.state_db == {}

    def test_refusing_state_set_journals_its_refusals(self, wasm):
        rt = HookRuntime()
        faults.refusing_state_set()(rt)
        rt.run(wasm)

        assert rt.state_db == {}
        assert [w.result for w in rt.state_journal] == [
            hookapi.RESERVE_INSUFFICIENT] * 4


class TestBothDeleteSpellings:
    """A zero length is a delete however the pointer was spelled — the fault
    layer classifies on the same test the builtin applies, so a predicate
    that selects deletes cannot miss half of them."""

    def test_the_control_deletes_both(self, wasm):
        rt = HookRuntime()
        rt.run(wasm, arg=9)
        assert DK1 not in rt.state_db and DK2 not in rt.state_db
        assert codes(rt.state_db[RK9]) == [0, 0]

    def test_both_are_classified_as_deletes(self, wasm):
        rt = HookRuntime()
        log = faults.refuse_state_set(rt)
        rt.run(wasm, arg=9)

        deletes = [c for c in log if c.is_delete]
        assert [c.key for c in deletes] == [DK1, DK2]
        assert all(c.value is None for c in deletes)

    def test_the_deletes_predicate_refuses_both(self, wasm):
        rt = HookRuntime()
        log = faults.refuse_state_set(
            rt, when=faults.deletes, code=hookapi.TOO_MANY_STATE_MODIFICATIONS)
        rt.run(wasm, arg=9)

        assert [c.key for c in log if c.refused] == [DK1, DK2]
        # neither delete was applied, so both values survive
        assert rt.state_db[DK1] == DV and rt.state_db[DK2] == DV
        assert codes(rt.state_db[RK9]) == [
            hookapi.TOO_MANY_STATE_MODIFICATIONS] * 2

    def test_a_refused_pointer_spelled_delete_journals_as_a_delete(self, wasm):
        rt = HookRuntime()
        faults.refuse_state_set(rt, when=faults.deletes,
                                code=hookapi.TOO_MANY_STATE_MODIFICATIONS)
        rt.run(wasm, arg=9)

        refused = [w for w in rt.state_journal
                   if w.result == hookapi.TOO_MANY_STATE_MODIFICATIONS]
        assert [(w.key, w.value) for w in refused] == [
            (DK1, None), (DK2, None)]


class TestStockPredicates:
    def test_every_refuses_admitted_calls_only(self, wasm):
        rt = HookRuntime()
        log = faults.refuse_state_set(rt, when=faults.every,
                                      code=hookapi.RESERVE_INSUFFICIENT)
        rt.run(wasm)
        assert log and all(c.refused for c in log)
        assert rt.state_db == {}

    def test_deletes_ignores_non_state_records(self):
        assert not faults.deletes(
            faults.FaultCall(name="emit", index=0, blob=b"x"))
        assert not faults.deletes(
            faults.FaultCall(name="etxn_reserve", index=0))
        assert faults.deletes(
            faults.FaultCall(name="state_set", index=0, key=b"k"))
        assert not faults.deletes(
            faults.FaultCall(name="state_set", index=0, key=b"k", value=b"v"))


class TestRefuseHost:
    def test_every_call_is_refused_and_logged(self, wasm):
        rt = emit_rt()
        log = faults.refuse_host(rt, "etxn_reserve", hookapi.TOO_SMALL)
        rt.run(wasm, arg=1)

        assert [(c.name, c.refused, c.result) for c in log] == [
            ("etxn_reserve", True, hookapi.TOO_SMALL)]
        assert log[0].args == (2,)
        assert codes(rt.state_db[RK2])[0] == hookapi.TOO_SMALL

    def test_control_the_same_run_unrefused(self, wasm):
        rt = emit_rt()
        rt.run(wasm, arg=1)
        assert codes(rt.state_db[RK2])[0] == 2

    def test_refusing_is_the_setup_shape(self, wasm):
        rt = emit_rt()
        setup = faults.refusing("etxn_reserve", hookapi.INTERNAL_ERROR)
        setup(rt)
        rt.run(wasm, arg=1)
        assert codes(rt.state_db[RK2])[0] == hookapi.INTERNAL_ERROR
