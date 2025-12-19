# --- Java int32 helpers ------------------------------------------------------


def to_int32(x: int) -> int:
    """Emulate Java's 32-bit signed int."""
    x &= 0xFFFFFFFF
    if x & 0x80000000:
        return x - 0x100000000
    return x


def java_urshift(x: int, n: int) -> int:
    """
    Emulate Java's >>> (unsigned right shift) on a 32-bit int.
    """
    return (x & 0xFFFFFFFF) >> n
