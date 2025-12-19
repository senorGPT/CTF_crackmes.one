from typing import List, Tuple
from relib.java import to_int32, java_urshift
from relib.utils import ceil


# PRNG implementation from rand() function
def java_rand_step(seed: int) -> int:
    """
    One step of the Java rand() function given in the crackme:

        seed ^= (seed << 7) & 65535;
        seed ^= seed >>> 9;
        seed ^= (seed << 8) & 65535;
        return seed;

    We emulate it on a 32-bit int, like Java.
    """
    seed = to_int32(seed)
    seed ^= (seed << 7) & 0xFFFF
    seed = to_int32(seed)
    seed ^= java_urshift(seed, 9)
    seed = to_int32(seed)
    seed ^= (seed << 8) & 0xFFFF
    seed = to_int32(seed)
    return seed


# Win implementation from inside while loop
def is_win(seed: int) -> Tuple[int, bool]:
    """
    Given current seed, perform one rand() step and
    return (new_seed, is_win).

    Win condition in the crackme: (rand() % 37) < 18
    """
    new_seed = java_rand_step(seed)
    win = (new_seed % 37) < 18
    return new_seed, win


def win_losses_to_string(win_losses: List[bool]) -> str:
    win_lose_string = ""
    for _ in win_losses:
        win_lose_string += "W" if _ else "L"
    return win_lose_string


def parse_win_lose_string(win_lose_string: str) -> List[bool]:
    """
    Convert a string like 'WLLW' or 'w l L W' to [True, False, False, True].

    Any character that is not `w` or `W` will be considered a loss
    """
    win_losses = []
    for char in win_lose_string:
        win_losses.append(True) if char.lower() == 'w' else win_losses.append(False)

    return win_losses


def find_matching_patterns(win_losses: List[bool]) -> List:
    found_matches = []
    rounds_played = len(win_losses)

    for seed in range(0, 65536+1): # inclusive, exclusive
        current_seed = seed
        found_match = True

        for i in range(rounds_played):
            current_seed, has_won = is_win(current_seed)
            if has_won != win_losses[i]:
                found_match = False
                break

        if found_match:
            found_matches.append([seed, current_seed])
    
    return found_matches

# TODO cleanup and refactor
# LWLLLWLWLLWLLLWWLLWW
def main(): 
    print(f"[+] Roulette PRNG SideKick")
    print(f"[+] Bet 1 for ~10 Spins and Record the Result of Each Win")
    print(f"[+] w/W for a Win, Any Other Character for a Loss")
    print()
    
    found_matches, found_match, win_losses = [], [], []

    path_choice = input("[+] p/P for Pattern Mode | s/S for Seed Mode (Pattern Mode Default): ")
    pattern_path = not (path_choice in ['s', 'S'])
    
    if pattern_path: # pattern path
        while len(found_matches) != 1:
            win_lose_string = input("Enter Win/Lose Pattern: ")
            new_win_losses = parse_win_lose_string(win_lose_string)

            print(f"[ ]\n[+] Interpreted Pattern: {win_losses_to_string(win_losses)}-{win_losses_to_string(new_win_losses)}")
            print("[+] Seed Brute Force Starting...")

            win_losses += new_win_losses

            found_matches = find_matching_patterns(win_losses)
            print(f"[ ]\n[+] Found {len(found_matches)} Number of Matching Seed(s):")

            for i in range(0, min(10, len(found_matches))):
                print(f"[-] {i + 1}. Seed: {found_matches[i]}")

            if len(found_matches) > 9:
                print(f"[-] +{len(found_matches) - 10} More Matches Found.")
            
            if len(found_matches) > 1:
                print(f"[!] Try Expanding the Search with a Longer Pattern - Just Add on the Rest of the Pattern.")

            if len(found_matches) > 0:
                found_match = found_matches[0]

        print(f"[ ]")
        print(f"[+] Found Matching Seed!\n[ ]\n[-] Starting Seed: {found_match[0]}\n[-] Current Seed: {found_match[1]}")

    else:
        seed_input = input("Enter Current Seed: ")
        # TODO validate seed input from user
        found_match = [0, seed_input]

    try:
        rounds_to_predict = 0
        while int(rounds_to_predict) == 0:
            rounds_to_predict = input("[ ]\nEnter How Many Rounds to Predict: ")
        rounds_to_predict = ceil(int(rounds_to_predict))
    except:
        print(f"[+] Current Win/Loss Pattern: {win_losses_to_string(win_losses)}")
        print(f"[!] Exiting Due to Non-Number Input")
        return

    round_multiplier, current_seed = 0, 0
    next_round_win_losses = []
    while True:
        print(f"[+] {'Round':<30} {'Should Bet':<30}")
        current_seed = found_match[1]
        for i in range(rounds_to_predict):
            current_seed, has_won = is_win(current_seed)
            print(f"[+] #{((i+1) + (round_multiplier * int(rounds_to_predict))):<30}: {has_won:<30}")
            next_round_win_losses.append(has_won)

        user_input = input(f"[?] Predict Another {str(rounds_to_predict)} Rounds (y/Y): ")
        if user_input not in ['y', 'Y']:
            break
        round_multiplier += 1
    
    print(f"[ ]\n[+] Pattern After Predictions: {win_losses_to_string(win_losses)}-{win_losses_to_string(next_round_win_losses)}")
    print(f"[+] Seed After Predictions: {current_seed}")


if __name__ == '__main__':
    main()
