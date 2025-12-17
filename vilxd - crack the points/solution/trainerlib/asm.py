"""
Small instruction encoders for patching (x86/x64).
"""

import struct


def jmp_rel32(src: int, dst: int) -> bytes:
    """
    Encode an x86/x64 near jump: `E9 <rel32>`.

    - `src`: absolute VA where the JMP instruction starts
    - `dst`: absolute VA to jump to
    - Displacement is computed relative to the next instruction: `dst - (src + 5)`.
    """
    disp = dst - (src + 5)
    return b"\xE9" + struct.pack("<i", disp)


def call_iat_rip(iat_va: int, call_insn_va: int) -> bytes:
    """
    Encode an x64 indirect call through an IAT slot: `FF 15 <disp32>`.

    This encodes: `call qword ptr [rip+disp32]`, where RIP is the next instruction.

    - `iat_va`: absolute VA of the IAT slot (the slot contains the function pointer)
    - `call_insn_va`: absolute VA where the CALL instruction starts
    - Displacement is computed as: `iat_va - (call_insn_va + 6)`.
    """
    disp = iat_va - (call_insn_va + 6)
    return b"\xFF\x15" + struct.pack("<i", disp)


def call_rel32(src: int, dst: int) -> bytes:
    """
    Encode an x86/x64 near call: `E8 <rel32>`.

    - `src`: absolute VA where the CALL instruction starts
    - `dst`: absolute VA to call
    - Displacement is computed relative to the next instruction: `dst - (src + 5)`.
    """
    disp = dst - (src + 5)
    return b"\xE8" + struct.pack("<i", disp)


