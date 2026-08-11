"""Replay SetHook float_sto vectors against hookz handlers.

Host source: xahaud:src/test/app/SetHook_test.cpp:6242+
Schema:      tests/host_vectors/float_sto_schema.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hookz import hookapi
from hookz.handlers.float import float_sto, float_sto_set
from host_vectors.float_sto_schema import (
    XFL_1234567,
    set_hook_float_sto_cases,
)

_BYTE_GOLDENS_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "host_vectors"
    / "float_sto_vectors.json"
)
_BYTE_GOLDENS = json.loads(_BYTE_GOLDENS_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def rt():
    import wasmtime

    from hookz.runtime import HookRuntime

    r = HookRuntime()
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    memory = wasmtime.Memory(store, wasmtime.MemoryType(wasmtime.Limits(1, None)))
    r._store = store
    r._memory = memory
    return r


def _place_cur_iss(rt, case):
    cur_ptr = iss_ptr = 0
    cur_len = iss_len = 0
    if case.currency_len == 3 and case.currency is not None:
        cur_ptr, cur_len = 100, 3
        rt._write_memory(cur_ptr, case.currency.encode("ascii"))
    elif case.currency_len == 20 and case.currency is not None:
        cur_ptr, cur_len = 100, 20
        rt._write_memory(cur_ptr, bytes.fromhex(case.currency))
    if case.issuer_hex is not None:
        iss_ptr, iss_len = 200, 20
        rt._write_memory(iss_ptr, bytes.fromhex(case.issuer_hex))
    return cur_ptr, cur_len, iss_ptr, iss_len


@pytest.mark.parametrize("case", set_hook_float_sto_cases(), ids=lambda c: c.id)
def test_set_hook_float_sto_vector(rt, case):
    cur_ptr, cur_len, iss_ptr, iss_len = _place_cur_iss(rt, case)
    # INVALID_ARGUMENT is hookapi.INVALID_ARGUMENT
    expect = case.expect_rc
    if case.id == "issuer_without_currency":
        expect = hookapi.INVALID_ARGUMENT
    if case.id == "invalid_float":
        expect = hookapi.INVALID_FLOAT

    got = float_sto(
        rt, 0, 64, cur_ptr, cur_len, iss_ptr, iss_len, case.xfl, case.field_code
    )
    assert got == expect, f"{case.id}: {got} != {expect} ({case.host_cite})"


def test_iou_sfamount_header_and_roundtrip(rt):
    """SetHook: float_sto(sfAmount) → 0x61 header; float_sto_set recovers XFL."""
    rt._write_memory(100, b"USD")
    rt._write_memory(200, b"\x01" * 20)
    n = float_sto(rt, 0, 64, 100, 3, 200, 20, XFL_1234567, hookapi.sfAmount)
    assert n == 49
    buf = rt._read_memory(0, 49)
    assert buf[0] == 0x61
    assert float_sto_set(rt, 0, 49) == XFL_1234567


@pytest.mark.parametrize(
    "case", _BYTE_GOLDENS["cases"], ids=lambda case: case["id"]
)
def test_float_sto_byte_golden_fixture(rt, case):
    """Replay independent serialized-byte goldens, not a hookz round trip.

    xahaud:src/test/app/SetHook_test.cpp:6242+
    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1146-1284
    """
    field_code = int(case["field_code"])
    if field_code not in (0, 0xFFFF_FFFF):
        rt._write_memory(100, b"USD")
        rt._write_memory(200, b"\x01" * 20)
        cur_ptr, cur_len, iss_ptr, iss_len = 100, 3, 200, 20
    else:
        cur_ptr = cur_len = iss_ptr = iss_len = 0

    got = float_sto(
        rt,
        0,
        64,
        cur_ptr,
        cur_len,
        iss_ptr,
        iss_len,
        int(case["xfl"]),
        field_code,
    )
    assert got == int(case["rc"])

    if "full_hex" in case:
        assert rt._read_memory(0, got) == bytes.fromhex(case["full_hex"])
    if "amount_hex" in case:
        header_len = len(bytes.fromhex(case.get("header_hex", "")))
        assert rt._read_memory(header_len, 8) == bytes.fromhex(
            case["amount_hex"]
        )


def test_field_type_ge16_header_encoding(rt):
    """type>=16, field<16: host packs field in high nibble of first header byte.

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1210-1214
    """
    # type=16, field=1 → field_code = (16<<16)|1
    field_code = (16 << 16) | 1
    rt._write_memory(100, b"\xab" * 20)
    rt._write_memory(200, b"\xcd" * 20)
    n = float_sto(rt, 0, 64, 100, 20, 200, 20, XFL_1234567, field_code)
    assert n == 50  # 2-byte header + 8 + 40
    hdr = rt._read_memory(0, 2)
    assert hdr[0] == (1 << 4)  # field in high nibble
    assert hdr[1] == 16


def test_short_mode_roundtrip_with_prepended_header(rt):
    float_sto(rt, 2, 8, 0, 0, 0, 0, XFL_1234567, 0xFFFFFFFF)
    rt._write_memory(0, b"\x60\x12")
    assert float_sto_set(rt, 0, 10) == XFL_1234567
