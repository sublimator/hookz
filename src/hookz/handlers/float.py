"""XFL floating point operations — compare, sum, negate, int, set, divide, sto, sto_set."""

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
    """XFL sign lives in bit 62, and set means *positive* (hook_float:is_negative)."""
    return xfl != 0 and not ((xfl >> 62) & 1)


def float_one(rt: HookRuntime) -> int:
    """Return XFL representation of 1.0."""
    return _float_to_xfl(1.0)


def float_compare(rt: HookRuntime, a: int, b: int, mode: int) -> int:
    if mode == 0:
        return hookapi.INVALID_ARGUMENT
    if mode == 0b111:
        return hookapi.INVALID_ARGUMENT
    if mode & ~0b111:
        return hookapi.INVALID_ARGUMENT
    fa = _xfl_to_float(a)
    fb = _xfl_to_float(b)
    if (mode & hookapi.COMPARE_EQUAL) and fa == fb:
        return 1
    if (mode & hookapi.COMPARE_LESS) and fa < fb:
        return 1
    if (mode & hookapi.COMPARE_GREATER) and fa > fb:
        return 1
    return 0


def float_sum(rt: HookRuntime, a: int, b: int) -> int:
    if a == 0:
        return b
    if b == 0:
        return a
    return _float_to_xfl(_xfl_to_float(a) + _xfl_to_float(b))


def float_negate(rt: HookRuntime, a: int) -> int:
    if a == 0:
        return 0
    return a ^ (1 << 62)


def float_int(rt: HookRuntime, xfl: int, decimal: int, absolute: int) -> int:
    if xfl == 0:
        return 0
    mantissa = _xfl_mantissa(xfl)
    exponent = _xfl_exponent(xfl)
    neg = ((xfl >> 62) & 1) == 0
    if decimal > 15:
        return hookapi.INVALID_ARGUMENT
    if neg and not absolute:
        return hookapi.CANT_RETURN_NEGATIVE
    shift = -(exponent + decimal)
    if shift > 15:
        return 0
    if shift < 0:
        return hookapi.TOO_BIG
    if shift > 0:
        mantissa //= (10 ** shift)
    return mantissa


def float_set(rt: HookRuntime, exp: int, mantissa: int) -> int:
    if mantissa == 0:
        return 0
    f = mantissa * (10.0 ** exp)
    result = _float_to_xfl(f)
    if result == 0:
        return hookapi.INVALID_FLOAT
    return result


# XFL limits, from xahaud hook_float (HookAPI.h)
_ONE = (1 << 62) | ((0 + 97) << 54) | 1000000000000000   # float_one, XFL 1.0
_MIN_MANTISSA = 1000000000000000
_MAX_MANTISSA = 9999999999999999
_MIN_EXPONENT = -96
_MAX_EXPONENT = 80


def _normalize_xfl(man: int, exp: int, neg: bool = False) -> int | None:
    """Port of hook_float::normalize_xfl. Returns the XFL, or None on overflow.

    Kept structurally identical to the C++ — including the two off-by-one
    nudges near the mantissa bounds, which are not equivalent to a plain
    multiply/divide by ten and do change results at the edges.
    """
    if man == 0:
        return 0
    if man < 0:
        man = -man
        neg = True

    mo = len(str(man)) - 1                      # integer log10
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

    if man == 0:
        return 0

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

    if exp < _MIN_EXPONENT or man == 0:
        return 0
    if exp > _MAX_EXPONENT:
        return None

    return (0 if neg else (1 << 62)) | ((exp + 97) << 54) | man


def float_multiply(rt: HookRuntime, a: int, b: int) -> int:
    """Port of hook_float::float_multiply_internal_parts.

    Exact integer arithmetic on the mantissas, truncating — NOT a float
    multiply. Going through a Python float rounds to nearest and diverged from
    the node on 25% of pool-scale operands, by one unit in the last place. Every
    payout in a hook that routes 64-bit maths through the XFL API (the usual
    trick to avoid __multi3) inherits that error.
    """
    if a == 0 or b == 0:
        return 0
    m1, e1 = _xfl_mantissa(a), _xfl_exponent(a)
    m2, e2 = _xfl_mantissa(b), _xfl_exponent(b)
    neg = _xfl_is_negative(a) != _xfl_is_negative(b)

    man_out = (m1 * m2) // 10 ** 15             # truncating, as the node does
    if man_out >= (1 << 64):
        return hookapi.XFL_OVERFLOW

    out = _normalize_xfl(man_out, e1 + e2 + 15, neg)
    return hookapi.XFL_OVERFLOW if out is None else out


def float_divide(rt: HookRuntime, a: int, b: int) -> int:
    """Port of HookAPI::float_divide_internal.

    Long division on the mantissas by repeated subtraction, one decimal digit
    at a time — not a float divide. `fixFloatDivide` changes the inner loop's
    comparison from `>` to `>=`, which moves results, so the amendment set
    decides which behaviour applies.
    """
    if b == 0:
        return hookapi.DIVISION_BY_ZERO
    if a == 0:
        return 0
    if b == _ONE:
        return a

    man1, exp1 = _xfl_mantissa(a), _xfl_exponent(a)
    man2, exp2 = _xfl_mantissa(b), _xfl_exponent(b)
    neg1, neg2 = _xfl_is_negative(a), _xfl_is_negative(b)

    if _normalize_xfl(man1, exp1) == 0:
        return 0

    # line the divisor up with the dividend, one order at a time
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

    neg3 = not ((neg1 and neg2) or (not neg1 and not neg2))
    out = _normalize_xfl(man3, exp3, neg3)
    return hookapi.XFL_OVERFLOW if out is None else out


def float_invert(rt: HookRuntime, a: int) -> int:
    if a == 0:
        return hookapi.DIVISION_BY_ZERO
    fa = _xfl_to_float(a)
    return _float_to_xfl(1.0 / fa)


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

    if length > 8:
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
