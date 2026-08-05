"""`hookz.testing.faults` — refusals with receipts.

Every fault test here keeps its paired control: the same run with nothing
refused, green, proving the injection is what changed the outcome and that
it actually reached the host boundary.
"""

from __future__ import annotations

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
    return accept(SBUF("noop"), 0);
}
"""

K1 = bytes([0x01]) + b"\x00" * 31
K2 = bytes([0x02]) + b"\x00" * 31
K3 = bytes([0x03]) + b"\x00" * 31
RK1 = bytes([0xF0, 0x01]) + b"\x00" * 30
RK2 = bytes([0xF0, 0x02]) + b"\x00" * 30
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
