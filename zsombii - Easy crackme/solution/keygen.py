import random
import argparse

KEY_TOTAL_VALUE = 4
KEY_LENGTH = 10


def is_valid(key: str) -> bool:
    points = 0
    for ch in key:
        points += 1 if (ord(ch) & 3) == 0 else 0
    return points == 4


def generate_good_and_bad_character_lists(char_range):
    good_characters, bad_characters = [], []
    for ch in char_range:
        if (ord(ch) & 3) == 0:
            good_characters.append(ch)
            continue
        bad_characters.append(ch)
    
    return good_characters, bad_characters


def generate_key(good_characters, bad_characters) -> str:
    rng = random.Random()
    bad_needed = KEY_LENGTH - KEY_TOTAL_VALUE
    key = rng.sample(good_characters, KEY_TOTAL_VALUE) + rng.sample(bad_characters, bad_needed)
    random.shuffle(key)
    
    return ''.join(key)


def main():
    parser = argparse.ArgumentParser(description="Key generator for zsombii - Easy crackme")
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=1,
        help="Number of keys to generate (default: 1)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Write generated keys to this file when generating multiple keys (default: keys.txt).",
    )
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count must be >= 1")

    printable_ascii = "".join(chr(c) for c in range(32, 127))
    good_characters, bad_characters = generate_good_and_bad_character_lists(printable_ascii)

    out_path = args.out
    if args.count > 1 and out_path is None:
        out_path = "keys.txt"

    out_f = open(out_path, "w", encoding="utf-8", newline="\n") if out_path else None
    try:
        for _ in range(args.count):
            key = generate_key(good_characters, bad_characters)
            print(f"[+] Key Wrapped in Quotes: \"{key}\"")
            if args.count > 1:
                if out_f is not None:
                    out_f.write(key + "\n")
    finally:
        if out_f is not None:
            out_f.close()


if __name__ == '__main__':
    main()
