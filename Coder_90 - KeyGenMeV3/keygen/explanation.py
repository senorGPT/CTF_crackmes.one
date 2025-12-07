"""
Explanation of bitwise operators and the rol function logic
"""

print("=" * 60)
print("1. LEFT SHIFT OPERATOR: <<")
print("=" * 60)
print("The << operator shifts bits to the LEFT (toward higher bit positions)")
print("It's equivalent to multiplying by 2^shift")
print()

# Example 1: Simple left shift
value = 0b0001  # Binary: 1 in decimal
print(f"Example 1: {value} << 2")
print(f"  Binary: {bin(value)} << 2")
print(f"  Result: {bin(value << 2)} = {value << 2} in decimal")
print(f"  Explanation: Bits moved left by 2 positions, zeros fill in on the right")
print()

# Example 2: Left shift with overflow
value = 0b1011  # Binary: 11 in decimal
print(f"Example 2: {value} << 3")
print(f"  Binary: {bin(value)} << 3")
print(f"  Result: {bin(value << 3)} = {value << 3} in decimal")
print(f"  Explanation: Bits moved left, but without masking, the number grows")
print()

# Example 3: In the context of rol
value = 0x55555555
shift = 12
print(f"Example 3: In rol function - {hex(value)} << {shift}")
print(f"  Original: {bin(value)[2:].zfill(32)}")
result = value << shift
print(f"  After << {shift}: {bin(result)[2:].zfill(64)} (note: it's now 44 bits!)")
print(f"  The leftmost 12 bits moved out, zeros filled in on the right")
print()

print("=" * 60)
print("2. RIGHT SHIFT OPERATOR: >>")
print("=" * 60)
print("The >> operator shifts bits to the RIGHT (toward lower bit positions)")
print("It's equivalent to integer division by 2^shift")
print()

# Example 1: Simple right shift
value = 0b1010  # Binary: 10 in decimal
print(f"Example 1: {value} >> 2")
print(f"  Binary: {bin(value)} >> 2")
print(f"  Result: {bin(value >> 2)} = {value >> 2} in decimal")
print(f"  Explanation: Bits moved right by 2 positions, zeros fill in on the left")
print()

# Example 2: In the context of rol
value = 0x55555555
width = 32
shift = 12
print(f"Example 2: In rol function - {hex(value)} >> {width - shift}")
print(f"  Original: {bin(value)[2:].zfill(32)}")
print(f"  We shift right by {width - shift} = {32 - shift} positions")
result = value >> (width - shift)
print(f"  After >> {width - shift}: {bin(result)[2:].zfill(32)}")
print(f"  The rightmost {width - shift} bits are lost, zeros fill in on the left")
print(f"  This gives us the bits that will wrap around to the right side!")
print()

print("=" * 60)
print("3. MODULO ASSIGNMENT OPERATOR: %=")
print("=" * 60)
print("The %= operator is shorthand for: variable = variable % value")
print("The % operator gives the remainder after division")
print()

# Example 1: Basic modulo
print("Example 1: Basic modulo operation")
print(f"  13 % 5 = {13 % 5}  (13 divided by 5 = 2 remainder 3)")
print(f"  20 % 8 = {20 % 8}  (20 divided by 8 = 2 remainder 4)")
print()

# Example 2: Why we use it in rol
print("Example 2: Why we use shift %= width in rol function")
print("  If someone tries to rotate by 50 bits in a 32-bit word:")
shift = 50
width = 32
print(f"    shift = {shift}, width = {width}")
print(f"    {shift} % {width} = {shift % width}")
print(f"    Rotating by 50 is the same as rotating by {shift % width}!")
print(f"    (Because after 32 rotations, you're back where you started)")
print()

# Example 3: The %= operator
print("Example 3: The %= operator")
shift = 50
width = 32
print(f"  Before: shift = {shift}")
shift %= width  # This is the same as: shift = shift % width
print(f"  After shift %= {width}: shift = {shift}")
print()

print("=" * 60)
print("4. WHY CHECK IF shift == 0?")
print("=" * 60)
print("If shift is 0, we're rotating by 0 positions, which means no rotation!")
print()

value = 0x55555555
shift = 0
print(f"Example: rol({hex(value)}, {shift})")
print(f"  If shift = 0, rotating left by 0 means the value stays the same")
print(f"  We can skip the expensive bit operations and just return the masked value")
print(f"  This is an optimization to avoid unnecessary calculations")
print()

print("=" * 60)
print("5. PUTTING IT ALL TOGETHER: How rol works")
print("=" * 60)
print("Let's trace through rol(0x55555555, 12) step by step:")
print()

value = 0x55555555
shift = 12
width = 32

print(f"Step 1: Create mask for {width}-bit word")
mask = (1 << width) - 1
print(f"  mask = (1 << {width}) - 1 = {hex(mask)}")
print(f"  This creates a mask with all {width} bits set to 1")
print()

print(f"Step 2: Normalize shift using modulo")
print(f"  shift = {shift} % {width} = {shift % width}")
print(f"  (In this case, {shift} < {width}, so it stays {shift})")
print()

print(f"Step 3: Check if shift == 0")
print(f"  shift = {shift}, so we continue (skip the early return)")
print()

print(f"Step 4: Mask the input value")
print(f"  value = {hex(value)} & {hex(mask)} = {hex(value & mask)}")
print(f"  This ensures we're working with exactly {width} bits")
print()

print(f"Step 5: Perform the rotation")
print(f"  Part A: value << shift")
left_part = (value << shift) & mask
print(f"    {hex(value)} << {shift} = {hex(value << shift)}")
print(f"    After masking: {hex(left_part)}")
print(f"    This moves the left {shift} bits out and brings zeros in from the right")
print()

print(f"  Part B: value >> (width - shift)")
right_part = value >> (width - shift)
print(f"    {hex(value)} >> {width - shift} = {hex(right_part)}")
print(f"    This gets the {shift} bits that were pushed out (they wrap around)")
print()

print(f"  Part C: Combine with OR operator |")
result = left_part | right_part
print(f"    {hex(left_part)} | {hex(right_part)} = {hex(result)}")
print(f"    The OR operator combines the two parts together")
print()

print(f"Final result: {hex(result)}")

