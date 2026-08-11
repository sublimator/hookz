#!/usr/bin/env python3
"""Generate hookz float host-vector fixtures from the HookzFloatVectors case list.

The C++ suite lives at (xahaud worktree):
  src/test/app/HookzFloatVectors_test.cpp

Until that suite is linked into the local ``rippled`` binary, this script
produces the same case shape using hookz's host-faithful handlers. Refresh
from a real host dump when available::

  x-run-tests -- ripple.app.HookzFloatVectors 2>&1 | \\
    sed -n '/HOOKZ_FLOAT_VECTORS_BEGIN/,/HOOKZ_FLOAT_VECTORS_END/p' \\
    > tests/fixtures/host_vectors/hookz_float_vectors.host.json

Usage (from hooks-testing root)::

  uv run python scripts/generate_float_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from hookz import hookapi  # noqa: E402
from hookz.handlers.float import (  # noqa: E402
    float_compare,
    float_divide,
    float_invert,
    float_mulratio,
    float_multiply,
    float_negate,
    float_one,
    float_set,
    float_sum,
)


def _t(type_: str, val: int | str) -> dict:
    return {"type": type_, "val": str(val)}


def _exp_u64(code: int) -> dict:
    """Map handler return to ExpectedU64 JSON leaf."""
    # handlers return XFL (>=0) or negative HookReturnCode
    if code < 0:
        return {"ok": False, "error": _t("error", code)}
    # treat as unsigned bit pattern
    u = code & 0xFFFF_FFFF_FFFF_FFFF
    return {"ok": True, "value": _t("u64", u)}


def _as_signed_u64(value: int) -> int:
    return value if value < (1 << 63) else value - (1 << 64)


def main() -> None:
    one = float_one(None) & 0xFFFF_FFFF_FFFF_FFFF

    set_cases: list[tuple[int, int]] = [
        (0, 0),
        (-5, 0),
        (50, 0),
        (-97, 1),
        (97, 1),
        (-96, 1),
        (80, 1),
        (0, 1),
        (0, 10),
        (0, 100),
        (0, 500),
        (0, 1000),
        (0, 10000),
        (0, 1_000_000_000_000_000),
        (0, 9_999_999_999_999_999),
        (0, 10_000_000_000_000_000),
        (0, 9_999_999_999_999_998),
        (0, 1_000_000_000_000_001),
        (0, (1 << 53) - 1),
        (0, 1 << 53),
        (0, (1 << 53) + 1),
        (0, (1 << 53) + 2),
        (0, (1 << 63) - 1),
        (0, (1 << 63) - 2),
        (0, -1),
        (0, -100),
        (0, -1_000_000_000_000_000),
        (0, -(1 << 63) + 1),
        (0, -(1 << 63)),
        (-5, 6541432897943971),
        (-83, 7906202688397446),
        (76, 4760131426754533),
        (37, -8019384286534438),
        (50, 5145342538007840),
        (-70, 4387341302202416),
        (-26, -1754544005819476),
        (36, 8261761545780560),
        (35, 7975622850695472),
        (17, -4478222822793996),
        (-53, 5506604247807835),
        (-60, 5120164869507050),
        (41, 5176113875683063),
        (-54, -3477931844992923),
        (21, 6345031894305479),
        (-23, 5091583691147091),
        (-33, 7509684078851678),
        (-72, -1847771838890268),
        (71, -9138413713437220),
        (28, 4933894067102586),
        (-15, 1_000_000_000_000_000),
        (0, 1_000_000_000_000_000),
    ]

    float_set_rows = []
    for exp, man in set_cases:
        r = float_set(None, exp, man)
        float_set_rows.append(
            {
                "exp": _t("i32", exp),
                "man": _t("i64", man),
                "result": _exp_u64(r),
            }
        )

    # sum pairs — mirror C++ suite
    sum_pairs: list[tuple[int, int]] = []
    sum_pairs.append((one, one))
    sum_pairs.append((one, float_negate(None, one) & 0xFFFF_FFFF_FFFF_FFFF))
    sum_pairs.append((6165492090242838528, 6074309077695428608))
    sum_pairs.append((1676857706508234512, 6396111470866104320))
    for base in ((1 << 53) - 10, 1 << 53, 9_000_000_000_000_000, 9_999_999_999_999_990):
        a = float_set(None, 0, base)
        b = float_set(None, 0, base + 1)
        if a >= 0 and b >= 0:
            sum_pairs.append((a & 0xFFFF_FFFF_FFFF_FFFF, b & 0xFFFF_FFFF_FFFF_FFFF))
    for man in (1, 1000, 1_000_000_000_000_000, 9_999_999_999_999_999, 1 << 53):
        a = float_set(None, 0, man)
        if a >= 0:
            sum_pairs.append(
                (a & 0xFFFF_FFFF_FFFF_FFFF, float_negate(None, a) & 0xFFFF_FFFF_FFFF_FFFF)
            )
    sum_pairs.append((7607324992379065667, 95785354843184473))
    sum_pairs.append((6507979072644559603, 422214339164556094))

    float_sum_rows = []
    for a, b in sum_pairs:
        r = float_sum(None, a, b)
        float_sum_rows.append(
            {"a": _t("u64", a), "b": _t("u64", b), "result": _exp_u64(r)}
        )

    EQUAL, LESS, GREATER = 1, 2, 4
    two = float_set(None, 0, 2) & 0xFFFF_FFFF_FFFF_FFFF
    cmp_cases: list[tuple[int, int, int]] = [
        (one, one, EQUAL),
        (one, two, LESS),
        (two, one, GREATER),
        (two, one, EQUAL),
        (one, two, GREATER | LESS),
        (one, two, 0),
        (one, two, 0b111),
    ]
    for base in (1 << 53, 9_000_000_000_000_000, 9_999_999_999_999_990):
        a = float_set(None, 0, base)
        b = float_set(None, 0, base + 1)
        if a >= 0 and b >= 0:
            au, bu = a & 0xFFFF_FFFF_FFFF_FFFF, b & 0xFFFF_FFFF_FFFF_FFFF
            for mode in (EQUAL, LESS, GREATER, GREATER | LESS):
                cmp_cases.append((au, bu, mode))
    # invalid encodings as unsigned -1
    inv = (1 << 64) - 1
    cmp_cases.append((inv, one, EQUAL))
    cmp_cases.append((one, inv, LESS))
    cmp_cases.append((inv, 0, 0))

    float_cmp_rows = []
    for a, b, mode in cmp_cases:
        r = float_compare(None, a if a < (1 << 63) else a - (1 << 64), b if b < (1 << 63) else b - (1 << 64), mode)
        # handlers take signed int for xfl from wasm; pass as Python int with bit pattern
        # float_compare uses _invalid_float which checks xfl < 0 for signed...
        # For inv as u64 max, in C++ it's uint64 cast. In Python we need to pass as signed -1
        # Recompute carefully:
        def as_signed(u: int) -> int:
            return u if u < (1 << 63) else u - (1 << 64)

        r = float_compare(None, as_signed(a), as_signed(b), mode)
        float_cmp_rows.append(
            {
                "a": _t("u64", a),
                "b": _t("u64", b),
                "mode": _t("i32", mode),
                "result": _exp_u64(r),
            }
        )

    mul_pairs = [
        (one, one),
        (one, two),
        (two, two),
    ]
    for base in (1_000_000_000_000_000, 9_000_000_000_000_000, 1 << 53):
        a = float_set(None, 0, base)
        b = float_set(None, 0, 2)
        if a >= 0 and b >= 0:
            mul_pairs.append((a & 0xFFFF_FFFF_FFFF_FFFF, b & 0xFFFF_FFFF_FFFF_FFFF))

    float_mul_rows = []
    for a, b in mul_pairs:
        def as_signed(u: int) -> int:
            return u if u < (1 << 63) else u - (1 << 64)
        r = float_multiply(None, as_signed(a), as_signed(b))
        float_mul_rows.append(
            {"a": _t("u64", a), "b": _t("u64", b), "result": _exp_u64(r)}
        )

    ten = float_set(None, 0, 10)
    carry = float_set(None, 0, 7_499_999_999_999_999)
    assert ten >= 0 and carry >= 0
    neg_ten = float_negate(None, ten)
    neg_carry = float_negate(None, carry)
    inv = (1 << 64) - 1
    mulratio_cases = [
        (ten, 0, 3, 2, "exact_positive"),
        (ten, 0, 1, 3, "positive_toward_zero"),
        (ten, 1, 1, 3, "positive_away_from_zero"),
        (neg_ten, 0, 1, 3, "negative_toward_zero"),
        (neg_ten, 1, 1, 3, "negative_away_from_zero"),
        (one, 0, 1, 0, "division_by_zero"),
        (0, 1, 1, 0, "zero_precedes_division_by_zero"),
        (inv, 0, 1, 0, "invalid_float_precedes_division_by_zero"),
        (one, 1, 0, 1, "zero_numerator"),
        (one, 1, 0xFFFF_FFFF, 1, "uint32_max_numerator"),
        (carry, 1, 4, 3, "rounding_carry_positive"),
        (neg_carry, 1, 4, 3, "rounding_carry_negative"),
    ]
    float_mulratio_rows = []
    for a, round_up, numerator, denominator, note in mulratio_cases:
        r = float_mulratio(
            None, _as_signed_u64(a), round_up, numerator, denominator
        )
        float_mulratio_rows.append(
            {
                "a": _t("u64", a),
                "round_up": _t("i32", round_up),
                "numerator": _t("u64", numerator),
                "denominator": _t("u64", denominator),
                "result": _exp_u64(r),
                "note": note,
            }
        )

    div_pairs = [
        (float_sum(None, one, one) & 0xFFFF_FFFF_FFFF_FFFF, one),  # 2/1
        (one, one),
        (two, one),
        (one, two),
        (one, 0),  # division by zero
    ]
    float_div_rows = []
    for a, b in div_pairs:
        def as_signed(u: int) -> int:
            return u if u < (1 << 63) else u - (1 << 64)
        r = float_divide(None, as_signed(a), as_signed(b) if b else 0)
        note = "div_by_zero" if b == 0 else ("div_by_one" if b == one else None)
        row = {"a": _t("u64", a), "b": _t("u64", b), "result": _exp_u64(r)}
        if note:
            row["note"] = note
        float_div_rows.append(row)

    inv_cases = [one, two, 0]
    float_inv_rows = []
    for a in inv_cases:
        r = float_invert(None, a)
        float_inv_rows.append({"a": _t("u64", a), "result": _exp_u64(r)})

    doc = {
        "version": 1,
        "suite": "ripple.app.HookzFloatVectors",
        "purpose": (
            "host-faithful oracle generated by scripts/generate_float_vectors.py "
            "from HookzFloatVectors_test.cpp case lists via hookz handlers "
            "(replace with live host dump when ripple.app.HookzFloatVectors is linked)"
        ),
        "value_encoding": (
            "typed {type,val} for u64|i64|i32|error — val is decimal string, "
            "no JSON number path"
        ),
        "host_cites": {
            "limits": "xahaud:src/xrpld/app/hook/HookAPI.h:39-42",
            "normalize_xfl": "xahaud:src/xrpld/app/hook/HookAPI.h:184-289",
            "float_one": "xahaud:src/xrpld/app/hook/HookAPI.h:291-292",
            "float_set": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:986-1005",
            "float_sum": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1105-1145",
            "float_compare": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1060-1099",
            "float_multiply": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1008-1021",
            "float_mulratio": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1023-1048",
            "float_mulratio_internal": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2540-2559",
            "iou_mulratio": "xahaud:src/libxrpl/protocol/IOUAmount.cpp:183-315",
            "float_divide": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2562-2636",
            "float_invert": "xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1356-1364",
            "invalid_float_gate": "xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3375-3392",
            "suite": "xahaud:src/test/app/HookzFloatVectors_test.cpp",
        },
        "float_one": _t("u64", one),
        "float_set": float_set_rows,
        "float_sum": float_sum_rows,
        "float_compare": float_cmp_rows,
        "float_multiply": float_mul_rows,
        "float_mulratio": float_mulratio_rows,
        "float_divide": float_div_rows,
        "float_invert": float_inv_rows,
    }

    # This is a self-oracle fallback, never the primary live-host fixture.
    # Keeping a distinct destination prevents an innocent local invocation
    # from replacing independently generated Xahau evidence.
    out = (
        ROOT
        / "tests/fixtures/host_vectors/hookz_float_vectors.generated.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {out} "
        f"set={len(float_set_rows)} sum={len(float_sum_rows)} "
        f"cmp={len(float_cmp_rows)} mul={len(float_mul_rows)} "
        f"mulratio={len(float_mulratio_rows)} "
        f"div={len(float_div_rows)} inv={len(float_inv_rows)}"
    )


if __name__ == "__main__":
    main()
