#!/usr/bin/python3
from Crypto.Cipher import AES
import itertools
import random
from util import *
from s1 import xor_buf
from base64 import b64decode

def main():
    c13()


def c13():
    block_size = 16
    secret_key = get_random_bytes(block_size)
    encryptor = lambda email_address: aes128_ecb_encode(secret_key, pkcs7_pad(c13_profile_for(email_address), block_size))
    decryptor = lambda cipher_text: c13_parse_kv(pkcs7_unpad(aes128_ecb_decode(secret_key, cipher_text), block_size))

    target_cipher_block = b''
    # The minimum amount of prefix padding to cause a duplicated block
    # will give us the target block in the next block
    for repeat_pad_size in range(2*block_size - 1, 3 * block_size):
        repeat_pad = b"A" * repeat_pad_size
        trick_email_address = repeat_pad + pkcs7_pad(b"admin", block_size) + b"@example.com"
        cipher_text = encryptor(trick_email_address)

        chunks = chunk(cipher_text, block_size)
        # If we have a repeat, the block after repeat is target
        next_is_target = False
        target_cipher_chunk = b''
        last_chunk = b''
        for c in chunks:
            if next_is_target:
                target_cipher_block = c
                break
            next_is_target = (c == last_chunk)
            last_chunk = c
        if target_cipher_block != b'':
            break

    if target_cipher_block == b'':
        raise RuntimeError("Didn't find target cipher block")

    # At some padding between 0..block_size the end block should
    # be 'user<pkcspadding>'. If so, replacing it with our
    # target cipher block should give us something which will decode
    # to our desired plaintext
    for padding_size in range(0 ,block_size):
        padded_email_address = (b"A" * padding_size) + b"@example.com"

        cipher_text = encryptor(padded_email_address);
        # Splice in target block
        cipher_text = bytearray(cipher_text)
        cipher_text[-block_size:] = target_cipher_block
        cipher_text = bytes(cipher_text)
        try:
            profile = decryptor(cipher_text)
            if profile[b"role"] == b"admin":
                print("S2C13 - did it! got an admin role")
                return
        except (KeyError, ValueError):
            pass

    print("S2C13 fail. Bad coder, no biscuit");


def c13_profile_for(email_address):
    email_address = email_address.replace(b'&', b'')
    email_address = email_address.replace(b'=', b'')
    profile = {
            b"email": email_address,
            b"uid": b"10",
            b"role": b"user",
            }
    return b'&'.join(map(lambda k: k + b'=' + profile[k], profile))


def c13_parse_kv(buf):
    kvs = buf.split(b'&')
    return dict(map(lambda buf: buf.split(b'='), kvs))


def c12():

    unknown_key = get_random_bytes(16)
    oracle = lambda pt: c12_encryption_oracle(unknown_key, pt)

    # Shim is number of bytes to fill a block
    (block_size, shim_size) = c12_discover_block_and_shim_sizes(oracle)
    print("S2C12 - found block size {}".format(block_size))

    is_ecb = c12_detect_ecb(oracle, block_size)
    print("S2C12 - is ECB?:  {}".format(is_ecb))

    known_bytes = bytearray()

    for index in range(0, 10 * block_size):
        block_index = index // block_size
        chunk_index = index % block_size
        
#        print("block_index {} chunk_index {}".format(block_index, chunk_index))

        needed_pad_len = (block_size - 1) - chunk_index
        needed_pad = bytes(needed_pad_len)

        trick_block = bytearray(block_size) + known_bytes
        trick_block = trick_block[-(block_size-1):]

        block_dictionary = c12_make_block_dictionary(oracle, block_size, trick_block)
        cipher_text = oracle(needed_pad)

        cipher_chunks = chunk(cipher_text, block_size)
        interesting_chunk = cipher_chunks[index // block_size]
#        print("C0: {}".format(interesting_chunk))
        try:
            plain_text_byte = block_dictionary[interesting_chunk]
        except KeyError:
            break
            
        known_bytes.append(plain_text_byte)
#        print("Got byte: {}".format(plain_text_byte))
#        print("Got known bytes: {}".format(known_bytes))

    plain_text = pkcs7_unpad(known_bytes, block_size)
    print("S2C12 - got msg: {}", plain_text.decode('ascii'))


def c12_make_block_dictionary(oracle, block_size, prefix):

    if len(prefix) != block_size - 1:
        raise RuntimeError("sanity violation: {} != {}".format(block_size-1, len(prefix)))

    d = {}
    for b in range(0, 256):
        msg = bytearray(prefix)
        msg.append(b)
        cipher_text = oracle(msg)
        cipher_chunks = chunk(cipher_text, block_size)
        d[cipher_chunks[0]] = b

    return d


def c12_detect_ecb(oracle, block_size):

    repeated_blocks = bytes(block_size * 4)
    cipher_text = oracle(repeated_blocks)
    chunks = chunk(cipher_text, block_size)
    distinct_chunks = set(chunks)
    return len(chunks) != len(distinct_chunks)


def c12_discover_block_and_shim_sizes(oracle):

    zero_len = len(oracle(b''))
    for shim_size in range(1, 1000):
        ct = oracle(bytes(shim_size))
        if len(ct) != zero_len:
            return (len(ct) - zero_len, shim_size - 1)

    raise RuntimeError("Failed to find block size up to {}".format(max_block_size))


def c12_encryption_oracle(key, chosen_plain_text):
    block_size = 16

    secret_suffix = b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
    msg = pkcs7_pad(chosen_plain_text + secret_suffix, block_size)

    return aes128_ecb_encode(key, msg)


def c11():
    block_size = 16 # we're doing AES128
    for i in range(10):
        plain_text = bytes(block_size * 10)    # A lot of repetition, which repeats under ECB
        cipher_text = c11_encrypt_ecb_or_cbc_oracle(plain_text)
        chunks = chunk(cipher_text, block_size)
        distinct_chunks = set(chunks)
        if len(chunks) != len(distinct_chunks):
            print("S2C11 - guess ECB!")
        else:
            print("S2C11 - guess CBC!")


def c11_encrypt_ecb_or_cbc_oracle(plain_text):
    block_size = 16
    key = get_random_bytes(block_size)

    prefix = get_random_bytes(10)
    suffix = get_random_bytes(10)
    msg = pkcs7_pad(prefix + plain_text + suffix, block_size)

    if random.random() >= 0.5:
        print("S2C11 - doing CBC")
        iv = get_random_bytes(16)
        return aes128_cbc_encode(key, iv, msg)
    else:
        print("S2C11 - doing ECB")
        return aes128_ecb_encode(key, msg)


def c10():
    cipher_text = slurp_base64_file("10.txt")
    iv = bytes(itertools.repeat(0, 16))
    key = b"YELLOW SUBMARINE"

    plain_text = aes128_cbc_decode(key, iv, cipher_text);
    print("S1C10 msg is {}".format(plain_text.decode('ascii')))
    recipher_text = aes128_cbc_encode(key, iv, plain_text);
    print("Re-encode matches? : {}".format(recipher_text == cipher_text))


def aes128_ecb_encode(key, plain_text):
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    return ecb_cipher.encrypt(plain_text)


def aes128_ecb_decode(key, plain_text):
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    return ecb_cipher.decrypt(plain_text)


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