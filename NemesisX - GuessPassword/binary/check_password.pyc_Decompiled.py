# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: check_password.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import bcrypt
import getpass
import sys
STORED_HASH = b'$2b$12$pBRbErJA/R.oPinWBAx4buejz59JCDiARNr07zSRrK/1F8jHpMzSm'

def check_password():
    try:
        pw = getpass.getpass('Masukkan password: ').encode()
    except:
        print('\nGagal membaca input.')
        sys.exit(1)
    try:
        if bcrypt.checkpw(pw, STORED_HASH):
            return True
        return False
    except:
        return False

def main():
    if check_password():
        print('Password benar, akses diberikan.')
        return
    print('Password salah.')
    sys.exit(2)
if __name__ == '__main__':
    main()