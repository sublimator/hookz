"""XFL (Xahau Floating Point) conversion utilities.

XFL is a 64-bit representation used by the Xahau hook API for amounts.
Layout: [sign:1][exponent:8][mantissa:54]
- sign bit: 1 = positive, 0 = negative (inverted from IEEE)
- exponent: biased by 97
- mantissa: 15-16 significant digits
"""


def xfl_to_float(xfl: int) -> float:
    """Convert XFL to Python float."""
    if xfl == 0:
        return 0.0
    negative = ((xfl >> 62) & 1) == 0
    exponent = ((xfl >> 54) & 0xFF) - 97
    mantissa = xfl & ((1 << 54) - 1)
    val = mantissa * (10.0 ** exponent)
    return -val if negative else val


def float_to_xfl(f: float) -> int:
    """Convert Python float to XFL."""
    if f == 0:
        return 0
    negative = f < 0
    f = abs(f)
    exponent = 0
    while f >= 1e16:
        f /= 10
        exponent += 1
    while f < 1e15 and f != 0:
        f *= 10
        exponent -= 1
    mantissa = int(f)
    xfl = mantissa & ((1 << 54) - 1)
    xfl |= ((exponent + 97) & 0xFF) << 54
    if not negative:
        xfl |= 1 << 62
    return xfl


def xfl_mantissa(xfl: int) -> int:
    if xfl == 0:
        return 0
    return xfl & ((1 << 54) - 1)


def xfl_exponent(xfl: int) -> int:
    if xfl == 0:
        return 0
    return ((xfl >> 54) & 0xFF) - 97
