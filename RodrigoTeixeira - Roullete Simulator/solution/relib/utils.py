

def ceil(x: float) -> int:
    i = int(x)           # truncates toward 0, like 3.7 -> 3, -2.3 -> -2
    if x > 0 and x != i:
        return i + 1     # bump up if it's positive and not already whole
    return i
