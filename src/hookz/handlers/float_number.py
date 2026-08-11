"""Host Number / IOUAmount arithmetic used by Hook float_sum / float_compare / mulRatio.

Ports (with xahaud:path:line cites):
  Number::Guard / normalize / operator+=
    xahaud:src/libxrpl/basics/Number.cpp:58-164 (Guard)
    xahaud:src/libxrpl/basics/Number.cpp:172-221 (normalize)
    xahaud:src/libxrpl/basics/Number.cpp:224-338 (operator+=)
  Number::operator<
    xahaud:include/xrpl/basics/Number.h:117-144
  IOUAmount::mulRatio
    xahaud:src/libxrpl/protocol/IOUAmount.cpp:182-314
  IOUAmount ranges
    xahaud:src/libxrpl/protocol/IOUAmount.cpp:54-58
"""

from __future__ import annotations

from dataclasses import dataclass


# xahaud:include/xrpl/basics/Number.h:52-57
_NUM_MIN_MAN = 1_000_000_000_000_000
_NUM_MAX_MAN = 9_999_999_999_999_999
_NUM_MIN_EXP = -32768
_NUM_MAX_EXP = 32768

# xahaud:src/libxrpl/protocol/IOUAmount.cpp:54-58 (same as HookAPI float limits)
_IOU_MIN_MAN = 1_000_000_000_000_000
_IOU_MAX_MAN = 9_999_999_999_999_999
_IOU_MIN_EXP = -96
_IOU_MAX_EXP = 80


class NumberOverflow(Exception):
    """std::overflow_error from Number / IOUAmount normalize."""


class Guard:
    """Number::Guard — 16 decimal sticky digits for correct rounding.

    xahaud:src/libxrpl/basics/Number.cpp:58-164
    """

    __slots__ = ("digits", "xbit", "sbit")

    def __init__(self) -> None:
        self.digits = 0  # u64, 16 nibbles of guard digits
        self.xbit = 0  # sticky non-zero shifted off the end
        self.sbit = 0  # sign of guard digits (1 = negative)

    def set_negative(self) -> None:
        # xahaud:src/libxrpl/basics/Number.cpp:99-101
        self.sbit = 1

    def set_positive(self) -> None:
        # xahaud:src/libxrpl/basics/Number.cpp:93-95
        self.sbit = 0

    def push(self, d: int) -> None:
        # xahaud:src/libxrpl/basics/Number.cpp:111-116
        self.xbit = 1 if (self.xbit or (self.digits & 0xF) != 0) else 0
        self.digits >>= 4
        self.digits |= (d & 0xF) << 60

    def pop(self) -> int:
        # xahaud:src/libxrpl/basics/Number.cpp:119-123
        d = (self.digits & 0xF000_0000_0000_0000) >> 60
        self.digits = (self.digits << 4) & 0xFFFF_FFFF_FFFF_FFFF
        return d

    def round(self) -> int:
        """Return 1 (up), -1 (down), or 0 (exact half / even policy).

        Default mode is to_nearest (thread-local default on host).
        xahaud:src/libxrpl/basics/Number.cpp:131-164
        """
        # to_nearest (default)
        if self.digits > 0x5000_0000_0000_0000:
            return 1
        if self.digits < 0x5000_0000_0000_0000:
            return -1
        if self.xbit:
            return 1
        return 0


@dataclass
class Number:
    """ripple::Number (normalized signed mantissa + exponent).

    xahaud:include/xrpl/basics/Number.h
    """

    mantissa: int = 0
    exponent: int = -2_147_483_648  # std::numeric_limits<int>::lowest() default zero

    def is_zero(self) -> bool:
        return self.mantissa == 0

    def normalize(self) -> None:
        # xahaud:src/libxrpl/basics/Number.cpp:172-221
        if self.mantissa == 0:
            self.mantissa = 0
            self.exponent = -2_147_483_648
            return
        negative = self.mantissa < 0
        m = -self.mantissa if negative else self.mantissa
        while m < _NUM_MIN_MAN and self.exponent > _NUM_MIN_EXP:
            m *= 10
            self.exponent -= 1
        g = Guard()
        if negative:
            g.set_negative()
        while m > _NUM_MAX_MAN:
            if self.exponent >= _NUM_MAX_EXP:
                raise NumberOverflow("Number::normalize 1")
            g.push(m % 10)
            m //= 10
            self.exponent += 1
        self.mantissa = m
        if self.exponent < _NUM_MIN_EXP or self.mantissa < _NUM_MIN_MAN:
            self.mantissa = 0
            self.exponent = -2_147_483_648
            return
        r = g.round()
        if r == 1 or (r == 0 and (self.mantissa & 1) == 1):
            self.mantissa += 1
            if self.mantissa > _NUM_MAX_MAN:
                self.mantissa //= 10
                self.exponent += 1
        if self.exponent > _NUM_MAX_EXP:
            raise NumberOverflow("Number::normalize 2")
        if negative:
            self.mantissa = -self.mantissa

    def iadd(self, y: Number) -> Number:
        # xahaud:src/libxrpl/basics/Number.cpp:224-338
        if y.is_zero():
            return self
        if self.is_zero():
            self.mantissa = y.mantissa
            self.exponent = y.exponent
            return self
        if self.mantissa == -y.mantissa and self.exponent == y.exponent:
            self.mantissa = 0
            self.exponent = -2_147_483_648
            return self

        xm = self.mantissa
        xe = self.exponent
        xn = 1
        if xm < 0:
            xm = -xm
            xn = -1
        ym = y.mantissa
        ye = y.exponent
        yn = 1
        if ym < 0:
            ym = -ym
            yn = -1

        g = Guard()
        if xe < ye:
            if xn == -1:
                g.set_negative()
            while xe < ye:
                g.push(xm % 10)
                xm //= 10
                xe += 1
        elif xe > ye:
            if yn == -1:
                g.set_negative()
            while xe > ye:
                g.push(ym % 10)
                ym //= 10
                ye += 1

        if xn == yn:
            xm += ym
            if xm > _NUM_MAX_MAN:
                g.push(xm % 10)
                xm //= 10
                xe += 1
            r = g.round()
            if r == 1 or (r == 0 and (xm & 1) == 1):
                xm += 1
                if xm > _NUM_MAX_MAN:
                    xm //= 10
                    xe += 1
            if xe > _NUM_MAX_EXP:
                raise NumberOverflow("Number::addition overflow")
        else:
            if xm > ym:
                xm = xm - ym
            else:
                xm = ym - xm
                xe = ye
                xn = yn
            while xm < _NUM_MIN_MAN:
                xm *= 10
                xm -= g.pop()
                xe -= 1
            r = g.round()
            if r == 1 or (r == 0 and (xm & 1) == 1):
                xm -= 1
                if xm < _NUM_MIN_MAN:
                    xm *= 10
                    xe -= 1
            if xe < _NUM_MIN_EXP:
                xm = 0
                xe = -2_147_483_648

        self.mantissa = xm * xn
        self.exponent = xe
        return self

    def __lt__(self, other: Number) -> bool:
        # xahaud:include/xrpl/basics/Number.h:117-144
        lneg = self.mantissa < 0
        rneg = other.mantissa < 0
        if lneg != rneg:
            return lneg
        if self.mantissa == 0:
            return other.mantissa > 0
        if other.mantissa == 0:
            return False
        if self.exponent > other.exponent:
            return lneg
        if self.exponent < other.exponent:
            return not lneg
        return self.mantissa < other.mantissa

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Number):
            return NotImplemented
        return self.mantissa == other.mantissa and self.exponent == other.exponent


def number_from_parts(mantissa: int, exponent: int) -> Number:
    """Number(man, exp) — constructs then normalize().

    xahaud:include/xrpl/basics/Number.h:201-205
    """
    n = Number(mantissa, exponent)
    n.normalize()
    return n


def iou_from_parts(mantissa: int, exponent: int) -> tuple[int, int]:
    """IOUAmount(man, exp) under STNumberSwitchover=true.

    xahaud:src/libxrpl/protocol/IOUAmount.cpp:66-85
    Uses Number normalize then clamps to IOU exponent range.
    """
    n = number_from_parts(mantissa, exponent)
    man, exp = n.mantissa, n.exponent
    if man == 0:
        return 0, -100  # zero sentinel — xahaud:include/xrpl/protocol/IOUAmount.h:122-126
    if exp > _IOU_MAX_EXP:
        raise NumberOverflow("value overflow")
    if exp < _IOU_MIN_EXP:
        return 0, -100
    return man, exp


def iou_add(man1: int, exp1: int, man2: int, exp2: int) -> tuple[int, int]:
    """IOUAmount += under STNumberSwitchover (Number path).

    xahaud:src/libxrpl/protocol/IOUAmount.cpp:142-144
    """
    a = number_from_parts(man1, exp1)
    b = number_from_parts(man2, exp2)
    a.iadd(b)
    if a.is_zero():
        return 0, -100
    if a.exponent > _IOU_MAX_EXP:
        raise NumberOverflow("value overflow")
    if a.exponent < _IOU_MIN_EXP:
        return 0, -100
    return a.mantissa, a.exponent


def iou_lt(man1: int, exp1: int, man2: int, exp2: int) -> bool:
    """IOUAmount::operator< via Number.

    xahaud:include/xrpl/protocol/IOUAmount.h:154-157
    """
    # Zero sentinels
    if man1 == 0 and man2 == 0:
        return False
    a = Number(man1, exp1 if man1 != 0 else -100)
    b = Number(man2, exp2 if man2 != 0 else -100)
    # Inputs from valid XFLs are already normalized; compare uses Number rules
    # without re-normalize that would re-apply guard rounding.
    if man1 != 0 and a.mantissa != 0:
        pass
    return a < b


def iou_eq(man1: int, exp1: int, man2: int, exp2: int) -> bool:
    # xahaud:include/xrpl/protocol/IOUAmount.h:148-151
    if man1 == 0 and man2 == 0:
        return True
    return exp1 == exp2 and man1 == man2


def mul_ratio(
    man: int, exp: int, num: int, den: int, round_up: bool
) -> tuple[int, int]:
    """ripple::mulRatio — more precision than man*num/den in 64-bit.

    xahaud:src/libxrpl/protocol/IOUAmount.cpp:182-314

    Host-test note (not a production arithmetic divergence):
      SetHook_test ``ASSERT_EQUAL`` for ``float_mulratio`` is *soft* —
      xahaud:src/test/app/SetHook_test.cpp:5424-5440 (macro body) accepts
      ``|Δmantissa| ≤ 5_000_000`` after aligning exponents by at most 1.
      Golden XFL integers in that suite are therefore not bit-exact oracles;
      bit-level mismatches of a few ULPs against those constants are expected
      after ``Number`` normalize (STNumberSwitchover default true —
      xahaud:src/libxrpl/protocol/IOUAmount.cpp:34-40) and still pass host.

    # todo:xahaud-bug-candidate
    # Host ``log10Floor`` does ``*lower_bound(...)`` then ``--index`` when
    # unequal (IOUAmount.cpp:213-218). If ``v`` is past the power table
    # (``lower_bound`` returns ``end()``), that dereference is undefined.
    # We clamp ``index`` to the last table entry instead of reading off the
    # end. Intermediate mulRatio values are documented as ≤ 2^96 < 10^29, so
    # the path is not hit in normal operation — still a footgun if the
    # table or bounds ever change.
    """
    if den == 0:
        raise ZeroDivisionError("division by zero")

    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:196-207 — powerTable 10^i
    power_table: list[int] = []
    cur = 1
    for _ in range(30):
        power_table.append(cur)
        cur *= 10

    def log10_floor(v: int) -> int:
        # xahaud:src/libxrpl/protocol/IOUAmount.cpp:210-219
        # Note: host returns -1 for v==0 via the lower_bound/*l path; we
        # short-circuit the same result without the end()-deref hazard.
        if v == 0:
            return -1
        # lower_bound: first element >= v
        lo, hi = 0, len(power_table)
        while lo < hi:
            mid = (lo + hi) // 2
            if power_table[mid] < v:
                lo = mid + 1
            else:
                hi = mid
        index = lo
        if index >= len(power_table):
            # Host would UB on *end(); clamp (see docstring).
            index = len(power_table) - 1
        elif power_table[index] != v:
            index -= 1
        return index

    def log10_ceil(v: int) -> int:
        # xahaud:src/libxrpl/protocol/IOUAmount.cpp:223-229
        lo, hi = 0, len(power_table)
        while lo < hi:
            mid = (lo + hi) // 2
            if power_table[mid] < v:
                lo = mid + 1
            else:
                hi = mid
        return lo

    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:231-232
    fl64 = log10_floor((1 << 63) - 1)  # max int64

    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:234-242
    neg = man < 0
    abs_man = -man if neg else man
    mul = abs_man * num  # uint128 on host; Python int is unbounded
    den128 = den
    low = mul // den128
    rem = mul - low * den128
    exponent = exp

    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:246-264
    if rem:
        # host: roomToGrow = fl64 - log10Ceil(low); low==0 → log10Ceil(0)=0
        # (lower_bound of 0 in [1,10,...] lands on index 0).
        room_to_grow = fl64 - (0 if low == 0 else log10_ceil(low))
        if room_to_grow > 0:
            # table only goes to 10^29; host indexes powerTable[roomToGrow]
            room_to_grow = min(room_to_grow, 29)
            exponent -= room_to_grow
            low *= power_table[room_to_grow]
            rem *= power_table[room_to_grow]
        add_rem = rem // den128
        low += add_rem
        rem = rem - add_rem * den128

    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:270-279
    has_rem = rem != 0
    must_shrink = (0 if low == 0 else log10_ceil(low)) - fl64
    if must_shrink > 0:
        sav = low
        exponent += must_shrink
        low //= power_table[must_shrink]
        if not has_rem:
            has_rem = (sav - low * power_table[must_shrink]) != 0

    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:281-287
    mantissa = int(low)
    if neg:
        mantissa = -mantissa

    # IOUAmount(mantissa, exponent) → normalize under STNumberSwitchover
    # xahaud:src/libxrpl/protocol/IOUAmount.cpp:67-85
    man_out, exp_out = iou_from_parts(mantissa, exponent)

    if has_rem:
        # xahaud:src/libxrpl/protocol/IOUAmount.cpp:289-311
        # Host re-constructs IOUAmount(man±1, exp) which re-normalizes; for a
        # normalized man in [min,max] the ±1 stays in-range except at the
        # extreme maxMantissa edge (constructor handles that).
        if round_up and not neg:
            if man_out == 0:
                # xahaud:src/libxrpl/protocol/IOUAmount.cpp:60-64 minPositiveAmount
                return _IOU_MIN_MAN, _IOU_MIN_EXP
            return iou_from_parts(man_out + 1, exp_out)
        if not round_up and neg:
            if man_out == 0:
                return -_IOU_MIN_MAN, _IOU_MIN_EXP
            return iou_from_parts(man_out - 1, exp_out)

    return man_out, exp_out
