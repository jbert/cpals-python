#!/usr/bin/python3
from Crypto.Cipher import AES
import itertools
from util import *

def main():
    c10()


def c10():
    cipher_text = slurp_base64_file("10.txt")
    iv = bytes(itertools.repeat(0, 16))
    key = b"YELLOW SUBMARINE"

    plain_text = aes128_cbc_decode(key, iv, cipher_text);
    print("S1C10 msg is {}".format(plain_text.decode('ascii')))
    recipher_text = aes128_cbc_encode(key, iv, plain_text);
    print("Re-encode matches? : {}".format(recipher_text == cipher_text))


def aes128_cbc_decode(key, iv, cipher_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(cipher_text)


def aes128_cbc_encode(key, iv, cipher_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(cipher_text)



if __name__ == "__main__":
    main()
