
import argparse
import struct
import sys
from pathlib import Path

from trainerlib import (
    K32,
    alloc_code_cave_near,
    call_rel32,
    hex_dump,
    image_base,
    jmp_rel32,
    launch_suspended,
    read_process_memory,
    write_process_memory,
    print_hex,
    wt,
)

# --- target-specific configuration ---
# RVAs are relative virtual addresses inside the module (not file offsets).
EXE_PATH = r"..\binary\point-cracker.exe"  # path to the EXE to run/patch
EDX_VALUE = 99  # value printed by printf (%d)

# Global logging switch (set by CLI)
QUIET = False


def log(*args, **kwargs) -> None:
    """Console logging controlled by --quiet."""
    if QUIET:
        return
    print(*args, **kwargs)


# All module-relative offsets (RVAs) used by this trainer.
RVA = {
    # **patch site**: overwrite 9 bytes with `jmp cave` (5 bytes) + `nop*4`.
    "patch_site": 0x11929,
    # NOTE: we no longer hardcode a code cave RVA; we allocate one with VirtualAllocEx.
    # **return** address after cave: after the 9-byte overwrite.
    # You showed the console-print call at RVA 0x11932, and 0x11929 + 9 == 0x11932.
    "return": 0x11937,
    # **printf format string** RVA ("Your count points is %d").
    "printf_format": 0x13000,
    # **printf IAT slot** RVA (slot contains imported function pointer).
    "printf_iat": 0x15E0,
    # sanity dump region (inclusive end)
    "sanity_dump_start": 0x11920,
    "sanity_dump_end_incl": 0x11976,
    "sanity_dump_end_main_incl": 0x11945,
    # 1-byte writable flag in .data (used for quick “did my cave run?” checks)
    "data_null_byte": 0x12008,
}


def print_comparison(name, old_site, patch):
    log(f"[+] {name} ({len(patch)} bytes):")
    log(f"    Old: {print_hex(old_site)}")
    log(f"    New: {print_hex(patch)}")


def write_and_check_memory(name, hproc, addr, patch, system_exit_code):
    log(f"[+] Writing {name}...")
    write_process_memory(hproc, addr, patch)
    if read_process_memory(hproc, addr, len(patch)) != patch:
        print("[-] Verify code cave failed", file=sys.stderr)
        raise SystemExit(system_exit_code)


def print_patch_intact(name, patch, hproc, addr, system_exit_code=5):
    site_now = read_process_memory(hproc, addr, len(patch))
    ok_site = site_now == patch

    if not ok_site:
        raise SystemExit(system_exit_code)
    
    log(f"[+] PatchSite {name} intact: {ok_site}")
    if not ok_site:
        log(f"    Expected: {patch.hex(' ').upper()}")
        log(f"    Actual:   {site_now.hex(' ').upper()}")


def print_dump_bytes(hproc, base, previous_dump: bytes | None = None, dump_rva_start = RVA["sanity_dump_start"], dump_rva_end = RVA["sanity_dump_end_incl"]):
    try:
        dump_start_va = base + dump_rva_start
        dump_len = (dump_rva_end - dump_rva_start) + 1
        dump_bytes = read_process_memory(hproc, dump_start_va, dump_len)

        log(
            f"[+] Dumping bytes: base+0x{dump_rva_start:X} -> base+0x{dump_rva_end:X} ({dump_len} bytes)"
        )
        if previous_dump is None:
            log(hex_dump(dump_bytes, dump_start_va))
            return dump_bytes

        # Compare mode: highlight changed bytes in red (ANSI).
        red = "\x1b[31m"
        reset = "\x1b[0m"
        use_color = sys.stdout.isatty()

        if len(previous_dump) != len(dump_bytes):
            log(f"[!] Previous dump length differs: {len(previous_dump)} != {len(dump_bytes)} (still diffing what we can)")

        width = 16
        for off in range(0, len(dump_bytes), width):
            chunk = dump_bytes[off : off + width]
            prev_chunk = previous_dump[off : off + width] if off < len(previous_dump) else b""

            parts: list[str] = []
            for i, b in enumerate(chunk):
                prev_b = prev_chunk[i] if i < len(prev_chunk) else None
                is_diff = prev_b is None or b != prev_b
                hx = f"{b:02X}"
                if use_color and is_diff:
                    hx = f"{red}{hx}{reset}"
                parts.append(hx)

            log(f"    0x{dump_start_va + off:016X}: " + " ".join(parts))
        
        return dump_bytes

    except OSError as e:
        print(f"[-] Sanity check failed: {e}", file=sys.stderr)
        raise SystemExit(5)


def main_trainer(exe: Path, *, edx_value: int) -> int:
    pid, hproc, hthread = launch_suspended(exe)
    try:
        base = image_base(hproc)

        addr          = base + RVA["patch_site"]        # patch site VA
        addr_flag     = base + RVA["data_null_byte"]    # 1-byte writable flag in .data (your "null byte" spot)

        # Allocate a real code cave (RWX) near the patch site so a rel32 JMP can reach it.
        # This avoids overwriting "maybe not actually free" bytes inside the module.
        cave_size = 0x1000
        addr_cave = alloc_code_cave_near(hproc, addr, cave_size)
        addr_return   = base + RVA["return"]            # return VA
        
        addr_str = base + RVA["printf_format"]  # printf format string VA
        addr_printf_wrapper = base + RVA["printf_iat"]  # printf IAT slot VA (contains pointer to printf)

        log(f"[+] PID:         {pid}")
        log(f"[+] ImageBase:   0x{base:016X}")
        log(f"[+] PatchSite:   RVA 0x{RVA['patch_site']:X} -> VA 0x{addr:016X}")
        log(f"[+] CodeCave:    VA  0x{addr_cave:016X}  (VirtualAllocEx)")
        log(f"[+] Return:      RVA 0x{RVA['return']:X} -> VA 0x{addr_return:016X}")
        log(f"[+] FormatStr:   RVA 0x{RVA['printf_format']:X} -> VA 0x{addr_str:016X}")
        log(f"[+] PrintF:      RVA 0x{RVA['printf_iat']:X}  -> VA 0x{addr_printf_wrapper:016X}")
        log(f"[+] EDX_VALUE:   {edx_value}")
        
        starting_bytes = print_dump_bytes(
            hproc, base,
            dump_rva_start=RVA["sanity_dump_start"],
            dump_rva_end=RVA["sanity_dump_end_main_incl"],
        )

        # Initialize flag = 0 (so we can detect it flipping to 1)
        write_process_memory(hproc, addr_flag, b"\x00")

        # --- trampoline: overwrite 9 bytes with jmp -> cave + nops ---
        disp = addr_cave - (addr + 5)
        if not (-0x8000_0000 <= disp <= 0x7FFF_FFFF):
            print(f"[-] Allocated cave is out of rel32 range for a 5-byte JMP. disp={disp}", file=sys.stderr)
            raise SystemExit(10)
        patch = jmp_rel32(addr, addr_cave) + (b"\x90" * 4)  # 5 + 4 = 9 bytes

        patch_cave = b"\xBA" + struct.pack("<I", edx_value & 0xFFFFFFFF)  # mov edx, imm32
        patch_cave += b"\x48\xB9" + struct.pack("<Q", addr_str)  # mov rcx, imm64 (absolute VA)

        # call qword ptr [rip+disp32] to printf IAT (6 bytes)
        call_addr = addr_cave + len(patch_cave)
        patch_cave += call_rel32(call_addr, addr_printf_wrapper)

        # jmp back to original flow (5 bytes)
        jmp_back_addr = addr_cave + len(patch_cave)
        patch_cave += jmp_rel32(jmp_back_addr, addr_return)

        old_site = read_process_memory(hproc, addr, len(patch))
        old_cave = read_process_memory(hproc, addr_cave, len(patch_cave))

        # --- write cave first, then arm trampoline ---
        write_process_memory(hproc, addr_cave, patch_cave)
        write_process_memory(hproc, addr, patch)

        print_dump_bytes(
            hproc, base,
            previous_dump=starting_bytes,
            dump_rva_start=RVA["sanity_dump_start"],
            dump_rva_end=RVA["sanity_dump_end_main_incl"],
        )

        print_comparison("Trampoline", old_site, patch)
        print_comparison("CodeCave Stub", old_cave, patch_cave)

        log("[+] Resuming.")
        K32.ResumeThread(wt.HANDLE(hthread))

        return 0

    finally:
        K32.CloseHandle(wt.HANDLE(hthread))
        K32.CloseHandle(wt.HANDLE(hproc))


def main(exe: Path) -> int:
    return main_trainer(exe, edx_value=EDX_VALUE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple trainer for point-cracker.exe (Windows)")
    parser.add_argument("--exe", default=EXE_PATH, help="Path to target EXE")
    parser.add_argument("--edx", type=lambda x: int(x, 0), default=EDX_VALUE, help="EDX value to pass to printf (%d). Supports 0x..")
    parser.add_argument("--quiet", action="store_true", help="Disable normal logging output")
    args = parser.parse_args()

    QUIET = bool(args.quiet)
    EDX_VALUE = int(args.edx)

    exe = Path(args.exe)
    if not exe.is_file():
        print(f"[-] EXE not found: {exe}", file=sys.stderr)
        raise SystemExit(1)

    raise SystemExit(main(exe))

