#!/usr/bin/python3
from random import choice
from util import pkcs7_pad, pkcs7_unpad, chunk, get_random_bytes
from s2 import aes128_cbc_encode, aes128_cbc_decode
from base64 import b64decode


def main():
    c17()


def c17():
    block_size = 16
    random_key = get_random_bytes(block_size)
    random_iv = get_random_bytes(block_size)

    cipher_text = c17_encryptor(block_size, random_key, random_iv)

    cipher_blocks = chunk(cipher_text, block_size)
    cipher_blocks.insert(0, random_iv)

    def c17_decryptor(cipher_text):
        return c17_decryptor_good_padding(block_size, random_key, random_iv, cipher_text)

    def break_one_block(i):
        return c17_break_block(cipher_blocks[i], cipher_blocks[i+1], c17_decryptor)

    len_cipher_blocks = len(cipher_blocks)
    plain_text = b''.join((map(break_one_block, range(0, len(cipher_blocks)-1))))
#    plain_text = bytearray(map(lambda t: c17_break_block(t[1], cipher_blocks[t[0]+1], c17_decryptor),
#                           filter(lambda t:  t[0]+1 < len(cipher_blocks), enumerate(cipher_blocks))))
    plain_text = pkcs7_unpad(plain_text, block_size)
    print("S3C17: {}".format(plain_text))


def c17_break_block(cblock_a, cblock_b, padding_oracle):
    block_size = len(cblock_a)
    assert block_size > 0
    assert len(cblock_a), len(cblock_b)

    # We work from the end backwards.
    # We want to guess a byte. Try all of them, xoring into the preceding block ciphertext
    # until we get good padding.
    # Then we know 'target_plain_text_byte XOR trial_byte == padding_byte'
    # So we can reverse to get target_plain_text_byte
    # Start at the end (padding 0x01) and work backwards to recover each byte (different
    # padding each time)
    attack_block = bytearray()
    xor_data = bytearray()
    recovered_plain_text = bytearray()
    for attack_index in range(block_size-1, -1, -1):
        desired_padding_byte = block_size - attack_index
        found_it = False
        for trial_byte in range(0, 256):
            attack_block[:] = cblock_a
            xor_data = bytearray(map(lambda b: b ^ desired_padding_byte, recovered_plain_text))
            xor_data.insert(0, trial_byte ^ desired_padding_byte)
            for (i, b) in enumerate(xor_data):
                attack_block[attack_index + i] = attack_block[attack_index + i] ^ b

            attack_cipher_text = bytearray()
            attack_cipher_text[:] = attack_block
            attack_cipher_text += cblock_b
            padding_ok = padding_oracle(attack_cipher_text)

            if padding_ok and attack_index > 0:
                # Also ensure byte before trial byte doesn't come out as 0x02, 0x03 etc (if there
                # is one)
                attack_block[attack_index - 1] = attack_block[attack_index - 1] ^ 0xf0
                attack_cipher_text[:] = attack_block
                attack_cipher_text += cblock_b
                second_padding_ok = padding_oracle(attack_cipher_text)
                padding_ok = second_padding_ok

            if padding_ok:
                recovered_plain_text.insert(0, trial_byte)
                found_it = True
                break

        if not found_it:
            raise RuntimeError("didn't find it")

    return recovered_plain_text


def c17_decryptor_good_padding(block_size, key, iv, cipher_text):
    padded_plain_text = aes128_cbc_decode(key, iv, cipher_text)
    try:
        pkcs7_unpad(padded_plain_text, block_size)
        # Good padding :-)
        return True
    except RuntimeError:
        # Bad padding :-(
        return False


def c17_encryptor(block_size, key, iv):
    target_b64_strings = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ]
    b64_string = choice(target_b64_strings)
    plain_text = b64decode(b64_string)
    padded_plain_text = pkcs7_pad(plain_text, block_size)
    return aes128_cbc_encode(key, iv, padded_plain_text)


if __name__ == "__main__":
    main()
