

def rol(value: int, shift: int, width: int = 32) -> int:
    """Rotate-left value by shift within a width-bit word."""
    # shift 0001 to the left by `width` and then subtract 1 to obtain a hex value of OxF* where F is repeated `width` amount
    # IE:   = 0001 << 32
    #       = 0001 0000 0000 0000 0000 0000 0000 0000 0000
    # -1    = 1111 1111 1111 1111 1111 1111 1111 1111
    mask = (1 << width) - 1
    shift %= width
    if shift == 0:
        return value & mask
    value &= mask
    # Standard rotate-left: (value << shift) | (value >> (width - shift))
    # Mask the final result to ensure 32-bit output
    return ((value << shift) | (value >> (width - shift))) & mask

#print("rol(0x55555555, 0xC) =", hex(rol(0x55555555, 0xC)))


# TODO write own rol function
# rotate left means you shift the bits left, and the bits that fall off the left
# end wrap around to the right end
def rotate_left(value: int, shift: int) -> int:
    print(hex(value))
    s_value = value << 1
    print(hex(s_value))


rotate_left(0x96, 0xC)
