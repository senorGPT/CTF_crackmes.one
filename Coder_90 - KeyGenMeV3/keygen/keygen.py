import utils

CONST_1 = 0x55555555
CONST_2 = 0xDEADC0DE

NAME_INPUT = "helloworld"
KEY_INPUT = "012345"

# acc = accumulator
def mix_even(char, acc, seed, index):
    utils.rol()


def mix_odd(char, acc, seed, index):
    pass


def main():
    acc = CONST_1
    seed = CONST_2

    # loop logic
    for index,char in enumerate(NAME_INPUT):
        if (int(char) % 2 == 0):
            mix_even(char, acc, seed, index)
        else:
            mix_odd(char, acc, seed, index)


if __name__ == "__main__":
    main()
