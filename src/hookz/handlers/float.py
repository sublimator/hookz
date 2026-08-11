"""XFL floating point operations — compare, sum, negate, int, set, divide, sto, sto_set.

Host sources (read-only xahaud checkout). Every ported branch should also carry
an inline ``xahaud:path:line`` cite at the behaviour itself.

* limits / sign / make_float / normalize / one:
  xahaud:src/xrpld/app/hook/HookAPI.h:39-42
  xahaud:src/xrpld/app/hook/HookAPI.h:59-83
  xahaud:src/xrpld/app/hook/HookAPI.h:145-172
  xahaud:src/xrpld/app/hook/HookAPI.h:184-289
  xahaud:src/xrpld/app/hook/HookAPI.h:291-292
* invalid-float gate (wrapper macro):
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3375-3392
* API wrappers (admission sites):
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3448-3456  (float_set)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3461-3477  (float_int)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3481-3494  (float_multiply)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3519-3528  (float_negate)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3531-3549  (float_compare)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3552-3565  (float_sum)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3667-3681  (float_divide)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3689-3701  (float_invert)
* API bodies:
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:986-1005   (float_set)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1008-1021  (float_multiply)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1023-1048  (float_mulratio)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1052-1057  (float_negate)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1060-1099  (float_compare)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1105-1145  (float_sum)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1356-1364  (float_invert)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1367-1369  (float_divide → internal)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1395-1428  (float_int)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1427-1441  (float_log)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1444-1461  (float_root)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2509-2537  (float_multiply_internal_parts)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2540-2559  (mulratio_internal)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2562-2636  (float_divide_internal)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2640-2690  (double_to_xfl)
* Number / IOUAmount arithmetic:
  xahaud:src/libxrpl/basics/Number.cpp
  xahaud:src/libxrpl/protocol/IOUAmount.cpp
* float_sto / float_sto_set:
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1146-1284  (float_sto)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1287-1350  (float_sto_set)
  xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3568-3663  (wrappers + bounds)
* host suite vectors:
  xahaud:src/test/app/SetHook_test.cpp:6082+ (float_set bounds + encodings)
  xahaud:src/test/app/SetHook_test.cpp:6242+ (float_sto / float_sto_set)
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi
from hookz.handlers.core import _not_in_bounds
from hookz.handlers.float_number import (
    NumberOverflow,
    iou_add,
    iou_eq,
    iou_from_parts,
    iou_lt,
    mul_ratio,
    number_from_parts,
)
from hookz.xfl import xfl_to_float as _xfl_to_float
from hookz.xfl import float_to_xfl as _float_to_xfl
from hookz.xfl import xfl_mantissa as _xfl_mantissa
from hookz.xfl import xfl_exponent as _xfl_exponent


def _xfl_is_negative(xfl: int) -> bool:
    """XFL sign lives in bit 62, and set means *positive*.

    xahaud:src/xrpld/app/hook/HookAPI.h:71-75 (is_negative)
    """
    return xfl != 0 and not ((xfl >> 62) & 1)


# xahaud:src/xrpld/app/hook/HookAPI.h:39-42
_MIN_MANTISSA = 1000000000000000
_MAX_MANTISSA = 9999999999999999
_MIN_EXPONENT = -96
_MAX_EXPONENT = 80
_INT64_MIN = -(1 << 63)
# xahaud:src/xrpld/app/hook/HookAPI.h:291-292
# make_float(1000000000000000ull, -15, false) — positive, exp bias (-15+97)=82.
# NOT exp=0 (that encodes value 1e15). set_exponent bias:
# xahaud:src/xrpld/app/hook/HookAPI.h:100-110.
_ONE = (1 << 62) | ((-15 + 97) << 54) | _MIN_MANTISSA


def float_one(rt: HookRuntime) -> int:
    """Return XFL representation of 1.0.

    xahaud:src/xrpld/app/hook/HookAPI.h:291-292 (float_one_internal)
    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1372-1375 (float_one API)
    """
    return _ONE


def _log10_order(man: int) -> int:
    """Host ``int32_t mo = log10(man)`` after double promote.

    xahaud:src/xrpld/app/hook/HookAPI.h:205-206
    C++ ``log10(double)`` then convert to int32 (trunc toward zero for >0).
    """
    # man > 0 always at this call site
    return int(math.log10(float(man)))


def _normalize_xfl(man: int, exp: int, neg: bool = False) -> int | None:
    """Port of hook_float::normalize_xfl.

    xahaud:src/xrpld/app/hook/HookAPI.h:184-289

    Returns the XFL, or None on overflow (host XFL_OVERFLOW). Underflow
    collapses to canonical 0. Includes the two off-by-one nudges near the
    mantissa bounds (HookAPI.h:240-259).
    """
    # xahaud:src/xrpld/app/hook/HookAPI.h:186-187
    if man == 0:
        return 0
    # xahaud:src/xrpld/app/hook/HookAPI.h:189-190
    if man == _INT64_MIN:
        man += 1
    # xahaud:src/xrpld/app/hook/HookAPI.h:195-202
    if man < 0:
        man = -man
        neg = True

    # xahaud:src/xrpld/app/hook/HookAPI.h:205-206
    mo = _log10_order(man)
    # xahaud:src/xrpld/app/hook/HookAPI.h:212-233
    adjust = 15 - mo
    if adjust > 0:
        if adjust > 18:
            return 0
        man *= 10 ** adjust
        exp -= adjust
    elif adjust < 0:
        if -adjust > 18:
            return None
        man //= 10 ** (-adjust)
        exp -= adjust

    # xahaud:src/xrpld/app/hook/HookAPI.h:235-238
    if man == 0:
        return 0

    # xahaud:src/xrpld/app/hook/HookAPI.h:240-259
    if man < _MIN_MANTISSA:
        if man == _MIN_MANTISSA - 1:
            man += 1
        else:
            man *= 10
            exp -= 1

    if man > _MAX_MANTISSA:
        if man == _MAX_MANTISSA + 1:
            man -= 1
        else:
            man //= 10
            exp += 1

    # xahaud:src/xrpld/app/hook/HookAPI.h:262-276
    if exp < _MIN_EXPONENT or man == 0:
        return 0
    if exp > _MAX_EXPONENT:
        return None

    # Host packs via make_float —
    # xahaud:src/xrpld/app/hook/HookAPI.h:145-172
    # exp bias +97: xahaud:src/xrpld/app/hook/HookAPI.h:100-110.
    return (0 if neg else (1 << 62)) | ((exp + 97) << 54) | man


def _make_float_parts(man: int, exp: int, neg: bool) -> int:
    """make_float(uint64_t mantissa, int32_t exponent, bool neg).

    xahaud:src/xrpld/app/hook/HookAPI.h:145-172
    Returns XFL, or a negative HookReturnCode on error (as host Unexpected).
    Underflow-sized exponents are reported by callers that map
    EXPONENT_UNDERSIZED → 0 (float_sum / double_to_xfl).
    """
    if man == 0:
        return 0
    if man > _MAX_MANTISSA:
        return hookapi.MANTISSA_OVERSIZED
    if man < _MIN_MANTISSA:
        return hookapi.MANTISSA_UNDERSIZED
    if exp > _MAX_EXPONENT:
        return hookapi.EXPONENT_OVERSIZED
    if exp < _MIN_EXPONENT:
        return hookapi.EXPONENT_UNDERSIZED
    return (0 if neg else (1 << 62)) | ((exp + 97) << 54) | man


def _xfl_signed_parts(xfl: int) -> tuple[int, int]:
    """(signed_mantissa, exponent) for a valid non-zero XFL."""
    man = _xfl_mantissa(xfl)
    exp = _xfl_exponent(xfl)
    if _xfl_is_negative(xfl):
        man = -man
    return man, exp


def _double_to_xfl(x: float) -> int:
    """HookAPI::double_to_xfl.

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2640-2690
    """
    if x == 0.0:
        return 0
    neg = x < 0
    absresult = -x if neg else x
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2648
    exp_out = int(math.log10(absresult))
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2652
    absresult *= 10.0 ** (-exp_out + 15)
    result = int(absresult)  # trunc toward zero
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2656-2676
    if result < _MIN_MANTISSA:
        if result == _MIN_MANTISSA - 1:
            result += 1
        else:
            result *= 10
            exp_out -= 1
    if result > _MAX_MANTISSA:
        if result == _MAX_MANTISSA + 1:
            result -= 1
        else:
            result //= 10
            exp_out += 1
    exp_out -= 15
    ret = _make_float_parts(result, exp_out, neg)
    if ret < 0:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2684-2687
        if ret == hookapi.EXPONENT_UNDERSIZED:
            return 0
        return ret
    return ret


def _invalid_float(xfl: int) -> int | None:
    """Port of applyHook RETURN_IF_INVALID_FLOAT. None if admitted.

    xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3375-3392
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3377-3378
    if xfl < 0:
        return hookapi.INVALID_FLOAT
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3379-3390
    if xfl == 0:
        return None
    man = _xfl_mantissa(xfl)
    exp = _xfl_exponent(xfl)
    if (man < _MIN_MANTISSA or man > _MAX_MANTISSA
            or exp > _MAX_EXPONENT or exp < _MIN_EXPONENT):
        return hookapi.INVALID_FLOAT
    return None


def float_compare(rt: HookRuntime, a: int, b: int, mode: int) -> int:
    """Compare two XFLs under a mode bitset.

    Admission first: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3541-3542
    Body:             xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1060-1099
    Uses signed man/exp + Number ordering (IOUAmount::operator</==):
      xahaud:include/xrpl/protocol/IOUAmount.h:148-157
      xahaud:include/xrpl/basics/Number.h:117-144
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3541-3542
    err = _invalid_float(a)
    if err is not None:
        return err
    err = _invalid_float(b)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1067-1071
    equal_flag = bool(mode & hookapi.COMPARE_EQUAL)
    less_flag = bool(mode & hookapi.COMPARE_LESS)
    greater_flag = bool(mode & hookapi.COMPARE_GREATER)
    not_equal = less_flag and greater_flag
    if (equal_flag and less_flag and greater_flag) or mode == 0:
        return hookapi.INVALID_ARGUMENT
    if mode & ~0b111:
        return hookapi.INVALID_ARGUMENT

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1073-1096
    try:
        if a == 0:
            man1, exp1 = 0, -100
        else:
            man1, exp1 = _xfl_signed_parts(a)
            man1, exp1 = iou_from_parts(man1, exp1)
        if b == 0:
            man2, exp2 = 0, -100
        else:
            man2, exp2 = _xfl_signed_parts(b)
            man2, exp2 = iou_from_parts(man2, exp2)

        if not_equal and not iou_eq(man1, exp1, man2, exp2):
            return 1
        if equal_flag and iou_eq(man1, exp1, man2, exp2):
            return 1
        if greater_flag and iou_lt(man2, exp2, man1, exp1):
            return 1
        if less_flag and iou_lt(man1, exp1, man2, exp2):
            return 1
        return 0
    except NumberOverflow:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1098-1100
        return hookapi.XFL_OVERFLOW


def float_sum(rt: HookRuntime, a: int, b: int) -> int:
    """Sum two XFLs via IOUAmount / Number (not IEEE).

    Admission first: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3557-3558
    Body:             xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1105-1145
    Addition:         xahaud:src/libxrpl/protocol/IOUAmount.cpp:142-144
                      (STNumberSwitchover → Number::operator+=)
    make_float(amt):  xahaud:src/xrpld/app/hook/HookAPI.h:121-142
    """
    err = _invalid_float(a)
    if err is not None:
        return err
    err = _invalid_float(b)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1107-1110
    if a == 0:
        return b
    if b == 0:
        return a

    try:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1112-1124
        man1, exp1 = _xfl_signed_parts(a)
        man2, exp2 = _xfl_signed_parts(b)
        man_out, exp_out = iou_add(man1, exp1, man2, exp2)
        if man_out == 0:
            return 0
        neg = man_out < 0
        abs_man = -man_out if neg else man_out
        # xahaud:src/xrpld/app/hook/HookAPI.h:121-142 make_float(IOUAmount)
        ret = _make_float_parts(abs_man, exp_out, neg)
        if ret < 0:
            # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1127-1135
            if ret == hookapi.EXPONENT_UNDERSIZED:
                return 0
            return ret
        return ret
    except NumberOverflow:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1139-1141
        return hookapi.XFL_OVERFLOW

def float_negate(rt: HookRuntime, a: int) -> int:
    """Flip XFL sign bit.

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3524
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1052-1057
    invert_sign: xahaud:src/xrpld/app/hook/HookAPI.h:77-83
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3524
    err = _invalid_float(a)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1054-1056
    if a == 0:
        return 0
    # xahaud:src/xrpld/app/hook/HookAPI.h:77-83 (invert_sign bit 62)
    return a ^ (1 << 62)


def float_int(rt: HookRuntime, xfl: int, decimal: int, absolute: int) -> int:
    """Project an XFL to an integer at a decimal place.

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3471
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1395-1428
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3471
    err = _invalid_float(xfl)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1398-1399
    if xfl == 0:
        return 0
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1400-1402
    mantissa = _xfl_mantissa(xfl)
    exponent = _xfl_exponent(xfl)
    neg = ((xfl >> 62) & 1) == 0
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1404-1405
    if decimal > 15:
        return hookapi.INVALID_ARGUMENT
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1407-1411
    if neg and not absolute:
        return hookapi.CANT_RETURN_NEGATIVE
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1413-1425
    shift = -(exponent + decimal)
    if shift > 15:
        return 0
    if shift < 0:
        return hookapi.TOO_BIG
    if shift > 0:
        mantissa //= (10 ** shift)
    return mantissa


def float_set(rt: HookRuntime, exp: int, mantissa: int) -> int:
    """Build an XFL from exponent and mantissa via integer normalize_xfl.

    Wrapper: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3448-3456
    Body:    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:986-1005
    Normalize: xahaud:src/xrpld/app/hook/HookAPI.h:184-289

    Not IEEE. Zero mantissa is canonical zero. Underflow and overflow both
    return INVALID_FLOAT — host maps XFL_OVERFLOW that way for float_set
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:997-1002).

    Harness history: a prior Python ``float``/IEEE ``float_to_xfl`` path lost
    1 ULP around 16-digit integers (e.g. ``(2**64-1)//10000``), which made
    tests for pre-serialization bucket debits look host-reproducible when
    they were not. Host ``normalize_xfl`` is integer; this port matches that,
    so those boundaries now round-trip exactly when the mantissa fits.
    """
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:988-989
    if mantissa == 0:
        return 0
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:991
    out = _normalize_xfl(mantissa, exp)
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:995-1002
    if out is None or out == 0:
        return hookapi.INVALID_FLOAT
    return out


def float_multiply(rt: HookRuntime, a: int, b: int) -> int:
    """Exact integer XFL multiply (truncate mantissa product, then normalize).

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3486-3487
    Outer:     xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1008-1021
    Inner:     xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2509-2537

    Not IEEE. A Python-float multiply rounds to nearest and diverged from the
    node on pool-scale operands by one unit in the last place.
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3486-3487
    err = _invalid_float(a)
    if err is not None:
        return err
    err = _invalid_float(b)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1010-1011
    if a == 0 or b == 0:
        return 0
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1013-1018
    m1, e1 = _xfl_mantissa(a), _xfl_exponent(a)
    m2, e2 = _xfl_mantissa(b), _xfl_exponent(b)
    neg = _xfl_is_negative(a) != _xfl_is_negative(b)

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2518-2522
    man_out = (m1 * m2) // 10 ** 15             # truncating, as the node does
    if man_out >= (1 << 64):
        return hookapi.XFL_OVERFLOW

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2524-2536
    out = _normalize_xfl(man_out, e1 + e2 + 15, neg)
    return hookapi.XFL_OVERFLOW if out is None else out


def float_divide(rt: HookRuntime, a: int, b: int) -> int:
    """Long-division XFL divide (mantissa repeated subtraction).

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3673-3674
    Outer:     xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1367-1369
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2562-2636

    ``fixFloatDivide`` changes the inner loop comparison from ``>`` to ``>=``
    (xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2565, 2595-2605).
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3673-3674
    err = _invalid_float(a)
    if err is not None:
        return err
    err = _invalid_float(b)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2566-2574
    if b == 0:
        return hookapi.DIVISION_BY_ZERO
    if a == 0:
        return 0
    if b == _ONE:
        return a

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2576-2584
    man1, exp1 = _xfl_mantissa(a), _xfl_exponent(a)
    man2, exp2 = _xfl_mantissa(b), _xfl_exponent(b)
    neg1, neg2 = _xfl_is_negative(a), _xfl_is_negative(b)
    if _normalize_xfl(man1, exp1) == 0:
        return 0

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2586-2600 (align divisor)
    while man2 > man1:
        man2 //= 10
        exp2 += 1
    if man2 == 0:
        return hookapi.DIVISION_BY_ZERO
    while man2 < man1:
        if man2 * 10 > man1:
            break
        man2 *= 10
        exp2 -= 1

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2565, 2595-2625
    has_fix = rt is None or "fixFloatDivide" in getattr(rt, "amendments", ())
    man3, exp3 = 0, exp1 - exp2
    while man2 > 0:
        i = 0
        if has_fix:
            while man1 >= man2:
                man1 -= man2
                i += 1
        else:
            while man1 > man2:
                man1 -= man2
                i += 1
        man3 = man3 * 10 + i
        man2 //= 10
        if man2 == 0:
            break
        exp3 -= 1

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2627-2636
    neg3 = not ((neg1 and neg2) or (not neg1 and not neg2))
    out = _normalize_xfl(man3, exp3, neg3)
    return hookapi.XFL_OVERFLOW if out is None else out


def float_invert(rt: HookRuntime, a: int) -> int:
    """1/x for an XFL via float_divide_internal(one, x).

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3694
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1356-1364
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3694
    err = _invalid_float(a)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1358-1363
    # zero → DIVISION_BY_ZERO; one → one; else divide(one, a).
    # float_divide re-admits and implements those short-circuits.
    return float_divide(rt, _ONE, a)


def _sto_field_header(field: int, typ: int) -> bytes:
    """ST field header for float_sto when not XRP and not short.

    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1197-1220
    """
    if field < 16 and typ < 16:
        return bytes([((typ & 0xFF) << 4) | (field & 0xFF)])
    if field >= 16 and typ < 16:
        return bytes([(typ & 0xFF) << 4, field & 0xFF])
    if field < 16 and typ >= 16:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1210-1214
        # field sits in the *high* nibble of the first byte (not a raw field byte).
        return bytes([((field & 0xFF) << 4), typ & 0xFF])
    return bytes([0, typ & 0xFF, field & 0xFF])


_CURRENCY_CODE_CHARS = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*<>(){}[]|"
)


def _expand_currency(currency: bytes) -> bytes | None:
    """Validate/expand the host's three-byte currency shorthand.

    xahaud:src/xrpld/app/hook/detail/applyHook.cpp:605-654
    """
    if len(currency) == 20:
        return currency
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:617-628
    if len(currency) != 3 or any(c not in _CURRENCY_CODE_CHARS for c in currency):
        return None
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:630-651
    padded = bytearray(20)
    padded[12:15] = currency
    return bytes(padded)


def float_sto(rt: HookRuntime, write_ptr: int, write_len: int,
              cur_ptr: int, cur_len: int,
              iss_ptr: int, iss_len: int,
              xfl: int, field_code: int) -> int:
    """Serialize an XFL amount into XRPL binary format.

    Wrapper: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3568-3636
    Body:    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1146-1284
    Host suite: xahaud:src/test/app/SetHook_test.cpp:6242+

    Wrapper enforces bounds / currency lengths / RETURN_IF_INVALID_FLOAT before
    the body. Body sizes the STO header, packs XRP drops or IOU man/exp, and
    optionally appends currency+issuer.
    """
    # Wrapper admission order is observable: output/currency/issuer checks all
    # precede RETURN_IF_INVALID_FLOAT.
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3586-3625
    if _not_in_bounds(rt, write_ptr, write_len):
        return hookapi.OUT_OF_BOUNDS

    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3590-3606
    if cur_len == 0:
        if cur_ptr != 0:
            return hookapi.INVALID_ARGUMENT
        currency = None
    else:
        if cur_len not in (3, 20):
            return hookapi.INVALID_ARGUMENT
        if _not_in_bounds(rt, cur_ptr, cur_len):
            return hookapi.OUT_OF_BOUNDS
        currency = _expand_currency(rt._read_memory(cur_ptr, cur_len))
        if currency is None:
            return hookapi.INVALID_ARGUMENT

    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3609-3622
    if iss_len == 0:
        if iss_ptr != 0:
            return hookapi.INVALID_ARGUMENT
        issuer = None
    else:
        if iss_len != 20:
            return hookapi.INVALID_ARGUMENT
        if _not_in_bounds(rt, iss_ptr, iss_len):
            return hookapi.OUT_OF_BOUNDS
        issuer = rt._read_memory(iss_ptr, iss_len)

    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3625
    err = _invalid_float(xfl)
    if err is not None:
        return err

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1154-1160
    field = field_code & 0xFFFF
    typ = field_code >> 16
    is_xrp = field_code == 0
    is_short = field_code == 0xFFFFFFFF  # amount only; no header/tail

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1173-1189
    if issuer is not None and currency is None:
        return hookapi.INVALID_ARGUMENT
    if issuer is None and currency is not None:
        return hookapi.INVALID_ARGUMENT

    has_issuer = issuer is not None
    if has_issuer:
        if is_xrp or is_short:
            return hookapi.INVALID_ARGUMENT
    elif not is_xrp and not is_short:
        return hookapi.INVALID_ARGUMENT

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1162-1171, 1191-1193
    if is_xrp or is_short:
        header = b""
    else:
        header = _sto_field_header(field, typ)
    bytes_needed = 8 + len(header) + (40 if has_issuer else 0)
    if bytes_needed > write_len:
        return hookapi.TOO_SMALL

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1222-1224
    man = _xfl_mantissa(xfl) if xfl != 0 else 0
    exp = _xfl_exponent(xfl) if xfl != 0 else 0
    neg = _xfl_is_negative(xfl)

    amt = bytearray(8)
    if is_xrp:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1226-1249
        # drops = man / 10^(-exp); shift = -exp.
        if man == 0:
            drops = 0
        else:
            shift = -exp
            if shift > 15:
                # todo:xahaud-bug-candidate
                # Host cites https://github.com/Xahau/xahaud/issues/586 here —
                # XFL_OVERFLOW when the integer drop conversion would need more
                # than 15 decades of shift. Track whether that issue is fixed
                # upstream before treating this as permanent API contract.
                # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1230-1233
                return hookapi.XFL_OVERFLOW
            if shift < 0:
                return hookapi.XFL_OVERFLOW
            drops = man // (10 ** shift) if shift > 0 else man
        amt[0] = (0b00000000 if neg else 0b01000000) + ((drops >> 56) & 0b111111)
        amt[1] = (drops >> 48) & 0xFF
        amt[2] = (drops >> 40) & 0xFF
        amt[3] = (drops >> 32) & 0xFF
        amt[4] = (drops >> 24) & 0xFF
        amt[5] = (drops >> 16) & 0xFF
        amt[6] = (drops >> 8) & 0xFF
        amt[7] = drops & 0xFF
    elif man == 0:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1250-1255
        amt[0] = 0b10000000
    else:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1256-1272
        exp_b = exp + 97
        amt[0] = (0b10000000 if neg else 0b11000000) + (exp_b >> 2)
        amt[1] = ((exp_b & 0b11) << 6) + ((man >> 48) & 0b111111)
        amt[2] = (man >> 40) & 0xFF
        amt[3] = (man >> 32) & 0xFF
        amt[4] = (man >> 24) & 0xFF
        amt[5] = (man >> 16) & 0xFF
        amt[6] = (man >> 8) & 0xFF
        amt[7] = man & 0xFF

    out = bytearray(header)
    out.extend(amt)
    if has_issuer and not is_xrp and not is_short:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1277-1281
        out.extend(currency[:20])  # type: ignore[index]
        out.extend(issuer[:20])  # type: ignore[index]

    rt._write_memory(write_ptr, bytes(out))
    return len(out)


def float_sign(rt: HookRuntime, a: int) -> int:
    """Return 1 if negative, 0 if positive/zero.

    Wrapper admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3704-3714
    Body: xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1387-1392
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3709  RETURN_IF_INVALID_FLOAT
    err = _invalid_float(a)
    if err is not None:
        return err
    if a == 0:
        return 0
    return 1 if ((a >> 62) & 1) == 0 else 0


def float_mantissa(rt: HookRuntime, a: int) -> int:
    """Extract mantissa from XFL.

    Wrapper admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3716-3726
    Body: xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1379-1384
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3721  RETURN_IF_INVALID_FLOAT
    err = _invalid_float(a)
    if err is not None:
        return err
    if a == 0:
        return 0
    return _xfl_mantissa(a)


def float_log(rt: HookRuntime, a: int) -> int:
    """log10(XFL) as XFL via double_to_xfl.

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3731-3743
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1428-1441
    double_to_xfl: xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2640-2690

    Host really does promote the mantissa through ``double`` + ``log10``;
    this is not a pure-integer path (unlike float_set / float_sum).
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3736
    err = _invalid_float(a)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1430-1436
    if a == 0:
        return hookapi.INVALID_ARGUMENT
    if _xfl_is_negative(a):
        return hookapi.COMPLEX_NOT_SUPPORTED
    man = _xfl_mantissa(a)
    exp = _xfl_exponent(a)
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1438-1441
    # double inp = (double)(man1); double result = log10(inp) + exp1;
    result = math.log10(float(man)) + exp
    return _double_to_xfl(result)


def float_root(rt: HookRuntime, a: int, n: int) -> int:
    """Nth root of XFL via double_to_xfl.

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3746-3758
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1445-1461
    double_to_xfl: xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2640-2690

    Host uses ``pow`` on a double rebuild of the XFL — same double path as
    float_log. Not IEEE-754 as a product requirement; it is "whatever the
    host's libm does," then ``double_to_xfl``.
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3751
    err = _invalid_float(a)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1447-1456
    if a == 0:
        return 0
    if n < 2:
        return hookapi.INVALID_ARGUMENT
    if _xfl_is_negative(a):
        return hookapi.COMPLEX_NOT_SUPPORTED
    man = _xfl_mantissa(a)
    exp = _xfl_exponent(a)
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1458-1460
    # double inp = (double)(man1)*pow(10, exp1);
    # double result = pow(inp, ((double)1.0f) / ((double)(n)));
    inp = float(man) * (10.0 ** exp)
    result = inp ** (1.0 / float(n))
    return _double_to_xfl(result)


def float_mulratio(
    rt: HookRuntime, a: int, round_up: int, numer: int, denom: int
) -> int:
    """Multiply XFL by numer/denom via host mulRatio (not IEEE).

    Admission: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3499-3514
    Body:      xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1023-1048
    mulratio_internal: xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2540-2559
    mulRatio: xahaud:src/libxrpl/protocol/IOUAmount.cpp:182-314

    SetHook ``ASSERT_EQUAL`` goldens for this API are soft (Δman ≤ 5e6) —
    see ``mul_ratio`` docstring. Not a host production defect.
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3508
    err = _invalid_float(a)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1030-1033
    if a == 0:
        return 0
    if denom == 0:
        return hookapi.DIVISION_BY_ZERO
    try:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1035-1047
        man = _xfl_mantissa(a)
        exp = _xfl_exponent(a)
        # host passes uint32 numerator/denominator straight through
        man_out, exp_out = mul_ratio(
            man, exp, int(numer) & 0xFFFF_FFFF, int(denom) & 0xFFFF_FFFF,
            bool(round_up),
        )
        if man_out == 0:
            return 0
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1042-1043 (defensive abs)
        if man_out < 0:
            man_out = -man_out
        # sign from input XFL, not from mulRatio (magnitude path)
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1045
        neg = _xfl_is_negative(a)
        ret = _make_float_parts(man_out, exp_out, neg)
        if ret < 0:
            # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1046-1047
            return ret
        return ret
    except NumberOverflow:
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2554-2557
        return hookapi.XFL_OVERFLOW
    except ZeroDivisionError:
        return hookapi.DIVISION_BY_ZERO

def float_sto_set(rt: HookRuntime, read_ptr: int, read_len: int) -> int:
    """Deserialize XRPL amount bytes into XFL.

    Wrapper: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3642-3663
    Body:    xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1287-1350
    Ends in ``normalize_xfl`` (HookAPI.h:184-289).
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3651-3652
    if read_len < 8:
        return hookapi.NOT_AN_OBJECT
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3655-3656
    if _not_in_bounds(rt, read_ptr, read_len):
        return hookapi.OUT_OF_BOUNDS
    data = rt._read_memory(read_ptr, read_len)
    upto = 0
    # Host accidentally narrows Bytes::size() to uint8_t before parsing, so
    # lengths wrap modulo 256. Preserve that observable behavior.
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1289-1292
    length = len(data) & 0xFF

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1293-1320
    # Skip ST field header when the buffer is longer than a bare 8-byte amount.
    # Host special-cases length==8 only (no header strip). length==48 (IOU
    # amount+currency+issuer without outer header) is *not* special-cased on
    # host — if the first byte looks like a header nibble pattern it will be
    # consumed. Callers of raw 48-byte issued amounts must present them as
    # the 8-byte amount alone, or with a real field header.
    if length > 8:
        hi = data[upto] >> 4
        lo = data[upto] & 0x0F
        if hi == 0 and lo == 0:
            # typecode >= 16 && fieldcode >= 16
            if length < 11:
                return hookapi.NOT_AN_OBJECT
            upto += 3
            length -= 3
        elif hi == 0 or lo == 0:
            if length < 10:
                return hookapi.NOT_AN_OBJECT
            upto += 2
            length -= 2
        else:
            upto += 1
            length -= 1

    if length < 8:
        return hookapi.NOT_AN_OBJECT

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1325-1347
    is_xrp = (data[upto] & 0b10000000) == 0
    is_negative = (data[upto] & 0b01000000) == 0
    exponent = 0
    if is_xrp:
        # todo:xahaud-bug-candidate
        # Host advances past the first amount byte without folding its low 6
        # bits into the mantissa (HookAPI.cpp:1329-1332), then reads the next
        # byte with an & 0x3F mask as if it were still in the IOU layout. That
        # drops the top 6 bits of the XRP/drops packing produced by float_sto
        # (HookAPI.cpp:1241-1242). IOU short/full paths are unaffected. Mirrored
        # for fidelity; do not "fix" here without an upstream change.
        upto += 1
    else:
        exponent = (data[upto] & 0b00111111) << 2
        upto += 1
        exponent += data[upto] >> 6
        exponent -= 97

    mantissa = (data[upto] & 0b00111111) << 48
    upto += 1
    mantissa += data[upto] << 40
    upto += 1
    mantissa += data[upto] << 32
    upto += 1
    mantissa += data[upto] << 24
    upto += 1
    mantissa += data[upto] << 16
    upto += 1
    mantissa += data[upto] << 8
    upto += 1
    mantissa += data[upto]

    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1349-1350
    if mantissa == 0:
        return 0
    out = _normalize_xfl(mantissa, exponent, is_negative)
    if out is None:
        # normalize_xfl propagates XFL_OVERFLOW through Expected.
        # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1349-1352
        # xahaud:src/xrpld/app/hook/HookAPI.h:275-276
        return hookapi.XFL_OVERFLOW
    return out
