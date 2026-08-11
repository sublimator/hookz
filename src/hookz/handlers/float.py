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
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1052-1057  (float_negate)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1060-1099  (float_compare)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1105-1145  (float_sum)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1356-1364  (float_invert)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1367-1369  (float_divide → internal)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1395-1428  (float_int)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2509-2537  (float_multiply_internal_parts)
  xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:2562-2636  (float_divide_internal)
* host suite vectors:
  xahaud:src/test/app/SetHook_test.cpp:6082+ (float_set bounds + encodings)
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hookz.runtime import HookRuntime

from hookz import hookapi
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


def _normalize_xfl(man: int, exp: int, neg: bool = False) -> int | None:
    """Port of hook_float::normalize_xfl.

    xahaud:src/xrpld/app/hook/HookAPI.h:184-289

    Returns the XFL, or None on overflow (host XFL_OVERFLOW). Underflow
    collapses to canonical 0. Kept structurally identical to the C++ —
    including the two off-by-one nudges near the mantissa bounds, which are
    not equivalent to a plain multiply/divide by ten and do change results at
    the edges.
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

    # Host: int32_t mo = log10(man) after double promote —
    # xahaud:src/xrpld/app/hook/HookAPI.h:205-206.
    # We use exact decimal digit count; known residual near maxMantissa/>2^53.
    mo = len(str(man)) - 1
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
    # (set_mantissa / set_exponent / set_sign). exp bias +97:
    # xahaud:src/xrpld/app/hook/HookAPI.h:100-110.
    return (0 if neg else (1 << 62)) | ((exp + 97) << 54) | man


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
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3541-3542 (before mode body)
    err = _invalid_float(a)
    if err is not None:
        return err
    err = _invalid_float(b)
    if err is not None:
        return err
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1067-1071
    if mode == 0:
        return hookapi.INVALID_ARGUMENT
    if mode == 0b111:
        return hookapi.INVALID_ARGUMENT
    if mode & ~0b111:
        return hookapi.INVALID_ARGUMENT
    # Host body uses signed man/exp + IOUAmount —
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1073-1096.
    # Residual: Python float compare (ULP risk at man ≥ 2^53).
    fa = _xfl_to_float(a)
    fb = _xfl_to_float(b)
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1087-1096
    if (mode & hookapi.COMPARE_EQUAL) and fa == fb:
        return 1
    if (mode & hookapi.COMPARE_LESS) and fa < fb:
        return 1
    if (mode & hookapi.COMPARE_GREATER) and fa > fb:
        return 1
    return 0


def float_sum(rt: HookRuntime, a: int, b: int) -> int:
    """Sum two XFLs.

    Admission first: xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3557-3558
    Body:             xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1105-1145
    """
    # xahaud:src/xrpld/app/hook/detail/applyHook.cpp:3557-3558 then
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1107-1110
    err = _invalid_float(a)
    if err is not None:
        return err
    err = _invalid_float(b)
    if err is not None:
        return err
    if a == 0:
        return b
    if b == 0:
        return a
    # Host: IOUAmount += + make_float —
    # xahaud:src/xrpld/app/hook/detail/HookAPI.cpp:1112-1137.
    # Residual: IEEE add path.
    return _float_to_xfl(_xfl_to_float(a) + _xfl_to_float(b))


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


def float_sto(rt: HookRuntime, write_ptr: int, write_len: int,
              cur_ptr: int, cur_len: int,
              iss_ptr: int, iss_len: int,
              xfl: int, field_code: int) -> int:
    """Serialize an XFL amount into XRPL binary format."""
    field = field_code & 0xFFFF
    typ = field_code >> 16
    is_xrp = (field_code == 0)
    is_short = (field_code == 0xFFFFFFFF)

    header = b""
    if not is_xrp and not is_short:
        if field < 16 and typ < 16:
            header = bytes([(typ << 4) | field])
        elif field >= 16 and typ < 16:
            header = bytes([(typ << 4), field])
        elif field < 16 and typ >= 16:
            header = bytes([field, typ])
        else:
            header = bytes([0, typ, field])

    currency = rt._read_memory(cur_ptr, cur_len) if cur_len > 0 else None
    issuer = rt._read_memory(iss_ptr, iss_len) if iss_len > 0 else None

    # Validation: currency and issuer must both be set or both be unset
    if currency is not None and issuer is None:
        return hookapi.INVALID_ARGUMENT
    if issuer is not None and currency is None:
        return hookapi.INVALID_ARGUMENT

    has_iou = currency is not None and issuer is not None
    if has_iou and currency == b"\x00" * 20 and issuer == b"\x00" * 20:
        has_iou = False

    # Validate field_code vs has_iou
    if has_iou and is_xrp:
        return hookapi.INVALID_ARGUMENT
    if has_iou and is_short:
        return hookapi.INVALID_ARGUMENT
    if not has_iou and not is_xrp and not is_short:
        return hookapi.INVALID_ARGUMENT

    # Check output buffer is large enough
    bytes_needed = 8 + len(header) + (40 if has_iou else 0)
    if bytes_needed > write_len:
        return hookapi.TOO_SMALL

    # Pad 3-char currency codes to 20 bytes (matches xahaud behavior)
    if currency is not None and len(currency) < 20:
        padded = bytearray(20)
        padded[12:12 + len(currency)] = currency
        currency = bytes(padded)

    neg = ((xfl >> 62) & 1) == 0 if xfl != 0 else False
    mantissa = _xfl_mantissa(xfl) if xfl != 0 else 0
    exponent = _xfl_exponent(xfl) if xfl != 0 else 0

    amt_bytes = bytearray(8)
    if is_xrp or (not has_iou and not is_short):
        # XRP encoding: shift mantissa by exponent to get drops
        if mantissa == 0:
            drops = 0
        else:
            shift = -exponent
            if shift > 15:
                return hookapi.XFL_OVERFLOW
            if shift < 0:
                return hookapi.XFL_OVERFLOW
            if shift > 0:
                drops = mantissa // (10 ** shift)
            else:
                drops = mantissa
        amt_bytes[0] = (0b01000000 if not neg else 0b00000000) + ((drops >> 56) & 0b00111111)
        amt_bytes[1] = (drops >> 48) & 0xFF
        amt_bytes[2] = (drops >> 40) & 0xFF
        amt_bytes[3] = (drops >> 32) & 0xFF
        amt_bytes[4] = (drops >> 24) & 0xFF
        amt_bytes[5] = (drops >> 16) & 0xFF
        amt_bytes[6] = (drops >> 8) & 0xFF
        amt_bytes[7] = drops & 0xFF
    else:
        mantissa = _xfl_mantissa(xfl)
        exponent = _xfl_exponent(xfl)
        if mantissa == 0:
            amt_bytes[0] = 0b10000000
        else:
            exp_biased = exponent + 97
            amt_bytes[0] = (0b11000000 if not neg else 0b10000000) + (exp_biased >> 2)
            amt_bytes[1] = ((exp_biased & 0b11) << 6) + ((mantissa >> 48) & 0b111111)
            amt_bytes[2] = (mantissa >> 40) & 0xFF
            amt_bytes[3] = (mantissa >> 32) & 0xFF
            amt_bytes[4] = (mantissa >> 24) & 0xFF
            amt_bytes[5] = (mantissa >> 16) & 0xFF
            amt_bytes[6] = (mantissa >> 8) & 0xFF
            amt_bytes[7] = mantissa & 0xFF

    out = bytearray(header)
    out.extend(amt_bytes)
    if has_iou and not is_xrp and not is_short:
        out.extend(currency[:20])
        out.extend(issuer[:20])

    rt._write_memory(write_ptr, bytes(out[:write_len]))
    return len(out)


def float_sign(rt: HookRuntime, a: int) -> int:
    """Return 1 if negative, 0 if positive/zero."""
    if a == 0:
        return 0
    return 1 if ((a >> 62) & 1) == 0 else 0


def float_mantissa(rt: HookRuntime, a: int) -> int:
    """Extract mantissa from XFL."""
    if a == 0:
        return 0
    return _xfl_mantissa(a)


def float_log(rt: HookRuntime, a: int) -> int:
    """Natural log of XFL, returned as XFL. Matches xahaud: log10(mantissa) + exponent."""
    if a == 0:
        return hookapi.INVALID_ARGUMENT
    if ((a >> 62) & 1) == 0:
        return hookapi.COMPLEX_NOT_SUPPORTED
    man = _xfl_mantissa(a)
    exp = _xfl_exponent(a)
    result = math.log10(float(man)) + exp
    return _float_to_xfl(result)


def float_root(rt: HookRuntime, a: int, n: int) -> int:
    """Nth root of XFL, returned as XFL."""
    if a == 0:
        return 0
    if n < 2:
        return hookapi.INVALID_ARGUMENT
    if ((a >> 62) & 1) == 0:
        return hookapi.COMPLEX_NOT_SUPPORTED
    f = _xfl_to_float(a)
    return _float_to_xfl(f ** (1.0 / n))


def float_mulratio(rt: HookRuntime, a: int, round_up: int, numer: int, denom: int) -> int:
    """Multiply XFL by ratio numer/denom."""
    if a == 0:
        return 0
    if denom == 0:
        return hookapi.DIVISION_BY_ZERO
    f = _xfl_to_float(a)
    result = f * numer / denom
    if round_up and result != 0:
        # Round away from zero
        import math as _m
        if result > 0:
            result = _m.ceil(result * 1e15) / 1e15
        else:
            result = _m.floor(result * 1e15) / 1e15
    return _float_to_xfl(result)


def float_sto_set(rt: HookRuntime, read_ptr: int, read_len: int) -> int:
    """Deserialize XRPL amount bytes into XFL. Mirrors HookAPI::float_sto_set."""
    data = rt._read_memory(read_ptr, read_len)
    upto = 0
    length = len(data)

    # Slot subfields contain the raw 8-byte native or 48-byte issued amount.
    # Other supported lengths include a one-, two-, or three-byte field header.
    if length > 8 and length != 48:
        hi = data[upto] >> 4
        lo = data[upto] & 0x0F
        if hi == 0 and lo == 0:
            upto += 3; length -= 3
        elif hi == 0 or lo == 0:
            upto += 2; length -= 2
        else:
            upto += 1; length -= 1

    if length < 8:
        return hookapi.NOT_AN_OBJECT

    is_xrp = (data[upto] & 0x80) == 0
    is_negative = (data[upto] & 0x40) == 0

    exponent = 0
    if is_xrp:
        upto += 1
    else:
        exponent = (data[upto] & 0x3F) << 2
        upto += 1
        exponent += data[upto] >> 6
        exponent -= 97

    mantissa = (data[upto] & 0x3F) << 48; upto += 1
    mantissa += data[upto] << 40; upto += 1
    mantissa += data[upto] << 32; upto += 1
    mantissa += data[upto] << 24; upto += 1
    mantissa += data[upto] << 16; upto += 1
    mantissa += data[upto] << 8; upto += 1
    mantissa += data[upto]

    if mantissa == 0:
        return 0

    # Normalize mantissa to 15-16 digit range (matches normalize_xfl in xahaud)
    if mantissa > 0:
        mo = int(math.log10(mantissa))
        adjust = 15 - mo
        if adjust > 0 and adjust <= 18:
            mantissa *= 10 ** adjust
            exponent -= adjust
        elif adjust < 0 and -adjust <= 18:
            mantissa //= 10 ** (-adjust)
            exponent -= adjust

        MIN_MANTISSA = 1_000_000_000_000_000
        MAX_MANTISSA = 9_999_999_999_999_999
        if mantissa < MIN_MANTISSA:
            mantissa *= 10
            exponent -= 1
        elif mantissa > MAX_MANTISSA:
            mantissa //= 10
            exponent += 1

    if mantissa == 0:
        return 0

    xfl = mantissa & ((1 << 54) - 1)
    xfl |= ((exponent + 97) & 0xFF) << 54
    if not is_negative:
        xfl |= 1 << 62
    return xfl
