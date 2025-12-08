import utils
import argparse
import sys
import subprocess
import platform

CONST_1 = 0x55555555
CONST_2 = 0xDEADC0DE

def mix_even(char, acc, seed, index, rax):                  # keygenme 0x7FF777641CE0
    acc = utils.rol(acc, 0xC)                               # rol edi, C
    acc ^= char                                             # xor edi, r8d
    acc += 0x90F01234                                       # add edi, 0x90F01234 (7FF777641CE6)

    acc = utils.mask(acc)

    acc, seed = mix_both(acc, seed, index, rax)             # 7FF777641CEC
    return acc, seed


def mix_both(acc, seed, index, rax):                        # keygenme 0x7FF777641CEC
    r8 = seed                                               # mov r8d, ecx
    r8 += index                                             # add r8d, edx

    seed = utils.mask(r8 + rax)                             # lea ecx, qword ptr ds:[r8+rax]
    seed ^= r8                                              # xor ecx, r8d
    acc ^= seed                                             # xor edi, ecx

    return acc, seed


def mix_odd(char, acc, seed, index, rax):                   # keygenme 0x7FF777641D17
    acc = utils.rol(acc, 0x1D)                              # rol edi, 0x1D
    acc += char                                             # add edi, r8d
    acc += 0xE5D4C3B3                                       # add edi, 0xE5D4C3B3

    acc = utils.mask(acc)

    acc, seed = mix_both(acc, seed, index, rax)             # jmp keygenme.7FF777641CEC
    return acc, seed


def encode_name_input(name_input):                         # keygen.0x7FF777641D0D
    rax = utils.mask(len(name_input))                      # call <JMP.&strlen>
    rax = utils.neg(rax)                                    # neg eax
    acc = CONST_1                                           # mov ecx, DEADC0DE
    seed = CONST_2                                          # mov edi, 55555555

    # loop logic
    for index, char in enumerate(name_input):              # movzx r8d, r8b
        if (ord(char) % 2 == 0):                            # test r8b, 1
            acc, seed = mix_even(                           # je keygenme.7FF777641CE0
                ord(char), acc, seed, index, rax
            )
        else:
            acc, seed = mix_odd(                            # 7FF777641D17
                ord(char), acc, seed, index, rax
            )

        # print('CHAR: ', char, ' | EDI: ', hex(acc).upper())

    return acc, seed


def encode_name_input_part_two(name_input):
    edi, ecx = encode_name_input(name_input)                # 7FF777641D0D

    edx = utils.imul_low(len(name_input), len(name_input))  # imul edx, edx
    eax = edx                                               # mov eax, edx
    eax = utils.shl(eax, 8)                                 # shl eax, 0x08
    eax = utils.mask(eax - edx)                             # sub eax, edx

    edi = utils.rol(edi, 0x1D)                              # rol edi, 1D
    edi = utils.mask(edi + ecx)                             # add edi, ecx
    edi = utils.mask(edi ^ eax)                             # xor edi, eax

    print('EDI: ', utils.phex(edi), ' | EAX: ', utils.phex(eax), ' | ECX: ', utils.phex(ecx))

    return edi, ecx


def main():
    parser = argparse.ArgumentParser(description='KeyGenMeV3 Key Generator')
    parser.add_argument('name', nargs='?', help='Name to generate key for (optional, will prompt if not provided)')
    args = parser.parse_args()

    inputted = False
    
    # Get name from command-line argument or prompt user
    if args.name:
        name = args.name
        print('NAME: ', name)
    else:
        name = input('Enter Name: ')
        inputted = True
    
    if not name:
        print('Error: Name cannot be empty', file=sys.stderr)
        sys.exit(1)
    
    edi, ecx = encode_name_input_part_two(name)
    key = utils.phex(edi)[2:]
    print('KEY IS:', key)
    
    # Copy key to clipboard
    try:
        if platform.system() == 'Windows':
            # Use Windows clip command
            subprocess.run(['clip'], input=key, text=True, check=True)
        else:
            # Try using xclip (Linux) or pbcopy (Mac)
            try:
                subprocess.run(['xclip', '-selection', 'clipboard'], input=key, text=True, check=True)
            except FileNotFoundError:
                try:
                    subprocess.run(['pbcopy'], input=key, text=True, check=True)
                except FileNotFoundError:
                    print('(Clipboard copy not available on this system)', file=sys.stderr)
        print('(Key copied to clipboard)')
    except Exception as e:
        print(f'(Failed to copy to clipboard: {e})', file=sys.stderr)

    if inputted:
        input('Press Enter to exit...')


if __name__ == "__main__":
    main()
