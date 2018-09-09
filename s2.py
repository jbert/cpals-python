#!/usr/bin/python3
from Crypto.Cipher import AES
import itertools
from util import *
from s1 import xor_buf

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


def aes128_cbc_encode(key, iv, plain_text):
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    block_size = ecb_cipher.block_size
    if len(plain_text) % block_size != 0:
        raise RuntimeError("CBC requires padding to block size")
    if len(iv) != block_size:
        raise RuntimeError("IV must be one block")

    plain_chunks = chunk(plain_text, block_size)

    last_cipher_chunk = iv
    cipher_chunks = []
    for pc in plain_chunks:
        next_cipher_chunk = ecb_cipher.encrypt(xor_buf(pc, last_cipher_chunk))
        cipher_chunks.append(next_cipher_chunk)
        last_cipher_chunk = next_cipher_chunk

    return b''.join(cipher_chunks)

def aes128_cbc_decode(key, iv, cipher_text):
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    block_size = ecb_cipher.block_size
    if len(cipher_text) % block_size != 0:
        raise RuntimeError("CBC requires padding to block size")
    if len(iv) != block_size:
        raise RuntimeError("IV must be one block")

    cipher_chunks = chunk(cipher_text, block_size)

    last_cipher_chunk = iv
    plain_chunks = []
    for cc in cipher_chunks:
        next_plain_chunk = xor_buf(last_cipher_chunk, ecb_cipher.decrypt(cc))
        plain_chunks.append(next_plain_chunk)
        last_cipher_chunk = cc

    return b''.join(plain_chunks)


def c9():
    block_size = 20
    msg = b"YELLOW SUBMARINE"
    padded_message = pkcs7_pad(msg, block_size)
    expected_padded_message = b"YELLOW SUBMARINE\x04\x04\x04\x04"
    print("S2C9 padded message correct: {}", padded_message == expected_padded_message)


if __name__ == "__main__":
    main()
