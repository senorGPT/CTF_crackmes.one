
def phex(value: int):
    return hex(value).upper()


def mask(value: int, width: int = 32) -> int:
    """
    Mask value to fit within a width-bit word.
    Returns the low 'width' bits of value, truncating higher bits.
    """
    _mask = (1 << width) - 1
    return value & _mask

def to_signed(x: int, width: int) -> int:
    """
    Convert unsigned value to signed within a fixed bit width.
    Interprets the value as two's complement signed integer.
    """
    x = mask(x, width)
    sign = 1 << (width - 1)
    return x - (1 << width) if (x & sign) else x


def to_unsigned(x: int, width: int) -> int:
    """
    Convert value to unsigned within a fixed bit width.
    Returns the low 'width' bits, treating as unsigned.
    """
    return mask(x, width)


def imul_low(a: int, b: int, width: int = 32) -> int:
    """
    Simulate 2/3-operand IMUL:
    result = low 'width' bits of (signed(a) * signed(b))
    """
    sa = to_signed(a, width)
    sb = to_signed(b, width)
    prod = sa * sb
    return to_unsigned(prod, width)


def neg(value: int, width: int = 32) -> int:
    """
    Two's complement negation within a fixed bit width.
    Equivalent to x86 NEG on a width-bit register.
    """
    mask = (1 << width) - 1
    value &= mask
    return (-value) & mask   # same as (0 - value) & mask


def shl(value: int, shift: int, width: int = 32) -> int:
    """
    Shift-left value by shift within a width-bit word.
    Equivalent to x86 SHL on a width-bit register.
    """
    mask = (1 << width) - 1
    return (value << shift) & mask


def rol(value: int, shift: int, width: int = 32) -> int:
    """Rotate-left value by shift within a width-bit word."""
    mask = (1 << width) - 1

    shift %= width
    if shift == 0:
        return value & mask

    value &= mask
    return ((value << shift) | (value >> (width - shift))) & mask

# print("rol(0x555555AB, 0xC) (12) =", hex(rol(0x555555AB, 0xC)))
# print("rol(0x555555AB, 0x20) (32) =", hex(rol(0x555555AB, 0x20)))
