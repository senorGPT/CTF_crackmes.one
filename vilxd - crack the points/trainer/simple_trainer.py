
import struct
import sys
import time
from pathlib import Path

from trainerlib import (
    INFINITE,
    K32,
    STILL_ACTIVE,
    call_rel32,
    exit_code,
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

# All module-relative offsets (RVAs) used by this trainer.
RVA = {
    # **patch site**: overwrite 9 bytes with `jmp cave` (5 bytes) + `nop*4`.
    "patch_site": 0x11929,
    # **code cave** location where we write our stub.
    "code_cave": 0x11955,
    # **return** address after cave: after the 9-byte overwrite.
    # You showed the console-print call at RVA 0x11932, and 0x11929 + 9 == 0x11932.
    "return": 0x11937,
    # **printf format string** RVA ("Your count points is %d").
    "printf_format": 0x13000,
    # **printf IAT slot** RVA (slot contains imported function pointer).
    "printf_iat": 0x15E0,
    # null byte in .data that will be used to test if we are writing successfully
    "data_null_byte": 0x12008,
    # sanity dump region (inclusive end)
    "sanity_dump_start": 0x11920,
    "sanity_dump_end_incl": 0x11976,
    # sanity dump region .data (inclusive end)
    "sanity_dump_data_start": 0x12008,
    "sanity_dump_data_end": 0x1200f,
}


def print_comparison(name, old_site, patch):
    print(f"[+] {name} ({len(patch)} bytes):")
    print(f"    Old: {print_hex(old_site)}")
    print(f"    New: {print_hex(patch)}")


def write_and_check_memory(name, hproc, addr, patch, system_exit_code):
    print(f"[+] Writing {name}...")
    write_process_memory(hproc, addr, patch)
    if read_process_memory(hproc, addr, len(patch)) != patch:
        print("[-] Verify code cave failed", file=sys.stderr)
        raise SystemExit(system_exit_code)


def print_patch_intact(name, patch, hproc, addr, system_exit_code=5):
    site_now = read_process_memory(hproc, addr, len(patch))
    ok_site = site_now == patch

    if not ok_site:
        raise SystemExit(system_exit_code)
    
    print(f"[+] PatchSite {name} intact: {ok_site}")
    if not ok_site:
        print(f"    Expected: {patch.hex(' ').upper()}")
        print(f"    Actual:   {site_now.hex(' ').upper()}")


def print_dump_bytes(hproc, base, previous_dump: bytes | None = None, dump_rva_start = RVA["sanity_dump_start"], dump_rva_end = RVA["sanity_dump_end_incl"]):
    try:
        dump_start_va = base + dump_rva_start
        dump_len = (dump_rva_end - dump_rva_start) + 1
        dump_bytes = read_process_memory(hproc, dump_start_va, dump_len)

        print(
            f"[+] Dumping bytes: base+0x{dump_rva_start:X} -> base+0x{dump_rva_end:X} ({dump_len} bytes)"
        )
        if previous_dump is None:
            print(hex_dump(dump_bytes, dump_start_va))
            return dump_bytes

        # Compare mode: highlight changed bytes in red (ANSI).
        red = "\x1b[31m"
        reset = "\x1b[0m"
        use_color = sys.stdout.isatty()

        if len(previous_dump) != len(dump_bytes):
            print(f"[!] Previous dump length differs: {len(previous_dump)} != {len(dump_bytes)} (still diffing what we can)")

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

            print(f"    0x{dump_start_va + off:016X}: " + " ".join(parts))
        
        return dump_bytes

    except OSError as e:
        print(f"[-] Sanity check failed: {e}", file=sys.stderr)
        raise SystemExit(5)


def main_trainer(exe: Path) -> int:
    pid, hproc, hthread = launch_suspended(exe)
    try:
        base = image_base(hproc)
        
        addr = base + RVA["patch_site"]  # patch site VA
        addr_cave = base + RVA["code_cave"]  # code cave VA
        addr_return = base + RVA["return"]  # return VA
        addr_str = base + RVA["printf_format"]  # printf format string VA
        addr_printf_wrapper = base + RVA["printf_iat"]  # printf IAT slot VA (contains pointer to printf)

        patch = jmp_rel32(addr, addr_cave) # EB = JMP rel8 (short jump)
        patch += b"\x90\x90\x90\x90"						# add the proceeding 4 NOPs

        patch_cave = b"\xBA" + struct.pack("<I", EDX_VALUE & 0xFFFFFFFF)  # mov edx, imm32
        patch_cave += b"\x48\xB9" + struct.pack("<Q", addr_str)  # mov rcx, imm64 (absolute VA)

        # call qword ptr [rip+disp32] to printf IAT (6 bytes)
        call_addr = addr_cave + len(patch_cave)
        patch_cave += call_rel32(call_addr, addr_printf_wrapper)

        # jmp back to original flow (5 bytes)
        jmp_back_addr = addr_cave + len(patch_cave)
        patch_cave += jmp_rel32(jmp_back_addr, addr_return)

        # patch_cave = b"\xCC" + patch_cave[1:]

        print(f"[+] PID:        {pid}")
        print(f"[+] ImageBase:   0x{base:016X}")
        print(f"[+] PatchSite:   RVA 0x{RVA['patch_site']:X} -> VA 0x{addr:016X}")
        print(f"[+] CodeCave:    RVA 0x{RVA['code_cave']:X} -> VA 0x{addr_cave:016X}")
        print(f"[+] Return:      RVA 0x{RVA['return']:X} -> VA 0x{addr_return:016X}")
        print(f"[+] FormatStr:   RVA 0x{RVA['printf_format']:X} -> VA 0x{addr_str:016X}")
        print(f"[+] PrintF:      RVA 0x{RVA['printf_iat']:X}  -> VA 0x{addr_printf_wrapper:016X}")
        print(f"[+] EDX_VALUE:   {EDX_VALUE}")

        old_site = read_process_memory(hproc, addr, len(patch))
        old_cave = read_process_memory(hproc, addr_cave, len(patch_cave))

        print_comparison("Trampoline", old_site, patch)
        print_comparison("CodeCave Stub", old_cave, patch_cave)

        write_and_check_memory("trampoline", hproc, addr_cave, patch, 2)

        write_and_check_memory("code cave stub", hproc, addr_cave, patch_cave, 3)

        print(f"[+] Sanity check (still suspended): sleeping {1:.2f}s then re-reading patch sites...")
        time.sleep(1)

        print_patch_intact("Trampoline (PatchSite)", patch, hproc, addr, 4)
        print_patch_intact("CodeCave", patch_cave, hproc, addr, 5)

        print_dump_bytes(hproc, base)

        print("[+] Sanity check passed; resuming.")
        K32.ResumeThread(wt.HANDLE(hthread))

        print("[+] Waiting for target process (press Ctrl+C to stop waiting)...")
        K32.WaitForSingleObject(wt.HANDLE(hproc), INFINITE)

        # Watch patch bytes for ~2 seconds (or until process exits)
        for i in range(40):
            code = exit_code(hproc)
            if code != STILL_ACTIVE:
                print(f"[!] Process exited quickly. ExitCode={code}")
                break

            time.sleep(0.05)
        else:
            print("[+] Patch remained intact for 2s after resume.")

        return 0
    finally:
        K32.CloseHandle(wt.HANDLE(hthread))
        K32.CloseHandle(wt.HANDLE(hproc)) 


def debugging(exe: Path) -> int:
    pid, hproc, hthread = launch_suspended(exe)
    try:
        base = image_base(hproc)
        addr = base + RVA["patch_site"]  # patch site VA

        print(f"[+] PID:        {pid}")
        print(f"[+] ImageBase:   0x{base:016X}")
        print(f"[+] PatchSite:   RVA 0x{RVA['patch_site']:X} -> VA 0x{addr:016X}")
        print(f"[+] EDX_VALUE:   {EDX_VALUE}")

        starting_bytes = print_dump_bytes(hproc, base, dump_rva_start = RVA["sanity_dump_data_start"], dump_rva_end = RVA["sanity_dump_data_end"])

        patch = b"\xCC\x90"
        write_process_memory(hproc, addr, patch, dump_rva_start = RVA["sanity_dump_data_start"], dump_rva_end = RVA["sanity_dump_data_end"])   # just for this test run - After writing trampoline, replace first byte at patch site with INT3
        
        # Watch patch bytes for ~2 seconds (or until process exits)
        for i in range(40):
            code = exit_code(hproc)
            if code != STILL_ACTIVE:
                print(f"[!] Process exited quickly. ExitCode={code}")
                break

            time.sleep(0.05)
        else:
            print("[+] Patch remained intact for 2s after resume.")
            print_dump_bytes(hproc, base, previous_dump=starting_bytes)

        return 0
    finally:
        K32.CloseHandle(wt.HANDLE(hthread))
        K32.CloseHandle(wt.HANDLE(hproc)) 


def main(exe: Path) -> int:
    # main_trainer(exe) # Main trainer logic
    debugging(exe) # Debugging trainer logic


if __name__ == "__main__":
    exe = Path(EXE_PATH)
    if not exe.is_file():
        print(f"[-] EXE not found: {exe}", file=sys.stderr)
        raise SystemExit(1)

    raise SystemExit(main(exe))

    
