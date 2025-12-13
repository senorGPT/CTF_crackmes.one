import bcrypt
import sys
import time
import queue
import threading
from pathlib import Path
from datetime import datetime

STORED_HASH = b'$2b$12$pBRbErJA/R.oPinWBAx4buejz59JCDiARNr07zSRrK/1F8jHpMzSm'


class TeeOutput:
    """Write output to both console and file."""
    def __init__(self, file_path: Path):
        self.file = file_path.open("w", encoding="utf-8")
        self.stdout = sys.stdout
        self.lock = threading.Lock()
    
    def write(self, text: str, end: str = "\n", flush: bool = False):
        """Write text to both stdout and file, mimicking print() behavior."""
        with self.lock:
            full_text = text + end
            self.stdout.write(full_text)
            self.file.write(full_text)
            if flush:
                self.stdout.flush()
                self.file.flush()
    
    def flush(self):
        with self.lock:
            self.stdout.flush()
            self.file.flush()
    
    def close(self):
        self.file.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def load_candidates(path: Path, start_line: int = 0):
    """Yield password candidates (as bytes) from a wordlist file.
    
    Args:
        path: Path to the wordlist file
        start_line: Line number to start from (0-indexed, 0 = start from beginning)
    """
    with path.open("rb") as f:  # read as bytes so we don't fight encodings
        line_num = 0
        for line in f:
            line = line.rstrip(b"\r\n")
            if not line:
                continue
            
            # Skip lines before start_line
            if line_num < start_line:
                line_num += 1
                continue
            
            line_num += 1
            yield line


def check_password(pw: bytes, stored_hash: bytes) -> tuple[bool, float]:
    """Check a single password and return (is_match, duration)."""
    check_start = time.perf_counter()
    is_match = bcrypt.checkpw(pw, stored_hash)
    check_end = time.perf_counter()
    return is_match, check_end - check_start


def brute_force(wordlist_path: Path, num_threads: int = None, tee_output=None, start_line: int = 0):
    """Test each candidate against the STORED_HASH using multiple threads.
    
    Args:
        wordlist_path: Path to the wordlist file
        num_threads: Number of threads to use
        tee_output: Output function for logging (or None for print)
        start_line: Line number to start from (0-indexed)
    """
    if num_threads is None:
        # Default to number of CPU cores, but cap at reasonable limit
        import os
        num_threads = min(os.cpu_count() or 4, 16)
    
    start_time = time.perf_counter()
    found_password = None
    found_lock = threading.Lock()
    total_checked = 0
    total_lock = threading.Lock()
    check_times = []
    times_lock = threading.Lock()
    last_progress_time = start_time
    
    # Load all candidates into a list (for progress tracking)
    candidates = list(load_candidates(wordlist_path, start_line))
    total_candidates = len(candidates)
    
    if total_candidates == 0:
        output = tee_output if tee_output else print
        if start_line > 0:
            output(f"[-] Wordlist {wordlist_path.name} has no candidates after line {start_line}")
        else:
            output(f"[-] Wordlist {wordlist_path.name} is empty")
        return False
    
    output = tee_output if tee_output else print
    if start_line > 0:
        output(f"[+] Starting brute force with {num_threads} thread(s) on {total_candidates} candidates (starting from line {start_line + 1})...")
    else:
        output(f"[+] Starting brute force with {num_threads} thread(s) on {total_candidates} candidates...")
    
    def worker():
        nonlocal found_password, total_checked, check_times
        
        while True:
            try:
                # Get next password with timeout to check if we should stop
                pw = candidate_queue.get(timeout=0.1)
            except queue.Empty:
                # Check if password was found by another thread
                with found_lock:
                    if found_password is not None:
                        break
                continue
            
            # Check if password already found
            with found_lock:
                if found_password is not None:
                    candidate_queue.task_done()
                    break
            
            # Check the password
            is_match, duration = check_password(pw, STORED_HASH)
            
            # Update statistics
            with total_lock:
                total_checked += 1
                current_total = total_checked
            
            with times_lock:
                check_times.append(duration)
            
            if is_match:
                with found_lock:
                    if found_password is None:  # First to find it
                        found_password = pw
                candidate_queue.task_done()
                break
            
            candidate_queue.task_done()
            
            # Progress reporting (thread-safe, but only one thread prints)
            nonlocal last_progress_time
            current_time = time.perf_counter()
            if current_time - last_progress_time >= 1.0 or current_total % 1000 == 0:
                with found_lock:
                    if found_password is None:
                        elapsed = current_time - start_time
                        with times_lock:
                            avg_time = sum(check_times) / len(check_times) if check_times else 0
                        rate = current_total / elapsed if elapsed > 0 else 0
                        progress_pct = (current_total / total_candidates) * 100
                        output = tee_output if tee_output else print
                        output(f"[.] {current_total}/{total_candidates} ({progress_pct:.1f}%) | Elapsed: {elapsed:.1f}s | Avg: {avg_time*1000:.2f}ms/check | Rate: {rate:.1f} checks/s", end="\r", flush=True)
                        last_progress_time = current_time
    
    # Create queue and fill it with candidates
    candidate_queue = queue.Queue()
    for pw in candidates:
        candidate_queue.put(pw)
    
    # Start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    
    # Wait for all candidates to be processed or password found
    candidate_queue.join()
    
    # Wait a moment for threads to finish
    for t in threads:
        t.join(timeout=1.0)
    
    elapsed = time.perf_counter() - start_time
    
    output = tee_output if tee_output else print
    if found_password:
        with times_lock:
            avg_time = sum(check_times) / len(check_times) if check_times else 0
        output(f"\n[+] Password FOUND: {found_password.decode(errors='replace')!r}")
        output(f"[+] Total time: {elapsed:.2f}s | Checks: {total_checked} | Avg per check: {avg_time*1000:.2f}ms")
        return True
    else:
        with times_lock:
            avg_time = sum(check_times) / len(check_times) if check_times else 0
        output(f"\n[-] Exhausted wordlist {wordlist_path.name} ({total_checked} candidates), no match.")
        output(f"[-] Total time: {elapsed:.2f}s | Avg per check: {avg_time*1000:.2f}ms")
        return False


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"Usage: {argv[0]} <wordlist.txt> or <directory> [--threads N] [--log-file FILE] [--start-line N]")
        print(f"       --threads N: Number of threads to use (default: CPU core count, max 16)")
        print(f"       --log-file FILE: Log file path (default: bruteforce_YYYYMMDD_HHMMSS.log)")
        print(f"       --start-line N: Start from line N (1-indexed, default: 1)")
        return 1
    
    # Parse optional arguments
    num_threads = None
    log_file = None
    start_line = 0  # 0-indexed internally
    args = []
    i = 1
    while i < len(argv):
        if argv[i] == "--threads" and i + 1 < len(argv):
            try:
                num_threads = int(argv[i + 1])
                if num_threads < 1:
                    print(f"[-] Thread count must be at least 1")
                    return 1
                i += 2
            except ValueError:
                print(f"[-] Invalid thread count: {argv[i + 1]}")
                return 1
        elif argv[i] == "--log-file" and i + 1 < len(argv):
            log_file = Path(argv[i + 1])
            i += 2
        elif argv[i] == "--start-line" and i + 1 < len(argv):
            try:
                start_line_input = int(argv[i + 1])
                if start_line_input < 1:
                    print(f"[-] Start line must be at least 1")
                    return 1
                start_line = start_line_input - 1  # Convert to 0-indexed
                i += 2
            except ValueError:
                print(f"[-] Invalid start line: {argv[i + 1]}")
                return 1
        else:
            args.append(argv[i])
            i += 1
    
    if len(args) != 1:
        print(f"Usage: {argv[0]} <wordlist.txt> or <directory> [--threads N] [--log-file FILE] [--start-line N]")
        return 1

    input_path = Path(args[0])
    
    # Set up logging
    if log_file is None:
        # Generate default log filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = Path(f"bruteforce_{timestamp}.log")
    
    tee_output = None
    try:
        with TeeOutput(log_file) as tee:
            tee_output = tee.write
            tee.write(f"[+] Logging output to: {log_file}")
            tee.write(f"[+] Session started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            tee.write("")
    
            # Collect wordlist files
            wordlist_files = []
            
            if input_path.is_file():
                # Single file provided
                wordlist_files = [input_path]
            elif input_path.is_dir():
                # Directory provided - find all .txt files
                wordlist_files = sorted(input_path.glob("*.txt"))
                if not wordlist_files:
                    tee.write(f"[-] No .txt files found in directory: {input_path}")
                    return 1
                tee.write(f"[+] Found {len(wordlist_files)} .txt file(s) in directory")
            else:
                tee.write(f"[-] Path not found (file or directory): {input_path}")
                return 1

            # Process each wordlist file
            try:
                result = 2
                for i, wordlist_path in enumerate(wordlist_files, 1):
                    if len(wordlist_files) > 1:
                        tee.write(f"\n[+] Processing wordlist {i}/{len(wordlist_files)}: {wordlist_path.name}")
                    
                    ok = brute_force(wordlist_path, num_threads, tee_output, start_line)
                    if ok:
                        result = 0  # Password found, exit successfully
                        break
                    
                    # If not the last file, add a separator
                    if i < len(wordlist_files):
                        tee.write("")  # Blank line between wordlists
                
                # All wordlists exhausted, no match found
                tee.write(f"\n[+] Session ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                return result
                
            except KeyboardInterrupt:
                tee.write("\n[!] Aborted by user.")
                tee.write(f"[+] Session ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                return 130
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
