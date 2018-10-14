#!/usr/bin/python3
from Crypto.Cipher import AES
import itertools
import random
from util import get_random_bytes, chunk, pkcs7_pad, pkcs7_unpad, slurp_base64_file, hexquote_chars
from s1 import xor_buf
from base64 import b64decode
from random import randrange


def main():
    c16()


def c16():
    block_size = 16
    random_key = get_random_bytes(block_size)
    random_iv = get_random_bytes(block_size)

    payload = bytearray(b";admin=true;")
    # Hide the special chars by flipping a bit in them
    payload[0] ^= 0x01
    payload[6] ^= 0x01
    payload[11] ^= 0x01

    # Assuming we don't know the prefix, we will try at each offset
    for offset in range(0, block_size):
        chosen_plain_text = b'A' * offset
        # Prepend a sacrificial block, in which we can flip bits
        chosen_plain_text += b'A' * block_size
        chosen_plain_text += payload

        cipher_text = bytearray(c16_encryptor(block_size, random_key, random_iv, chosen_plain_text))
        # We don't know which block to flip. Let's try 'em all
        for block_index in range(0, (len(cipher_text) // block_size) - 1):
            # Flip the corresponding bits in the sacrificial block
            cipher_text[(block_index * block_size) + offset + 0] ^= 0x01;
            cipher_text[(block_index * block_size) + offset + 6] ^= 0x01;
            cipher_text[(block_index * block_size) + offset + 11] ^= 0x01;
            try:
                if (c16_decryptor(block_size, random_key, random_iv, bytes(cipher_text))):
                    print("S2C16 got admin")
                    return
            except Exception(e):
                # pkcs 7 fail?
                pass

    print("S2C16 fail :-(")



def c16_encryptor(block_size: int, key, iv, plain_text):
    buf = hexquote_chars(b";=", plain_text)
    buf = b"comment1=cooking%20MCs;userdata=" + buf + b";comment2=%20like%20a%20pound%20of%20bacon"
    padded_buf = pkcs7_pad(buf, block_size)
    return aes128_cbc_encode(key, iv, padded_buf)


def c16_decryptor(block_size, key, iv, cipher_text) -> bool:
    padded_plain_text = aes128_cbc_decode(key, iv, cipher_text)
    plain_text = pkcs7_unpad(padded_plain_text, block_size)
    return b";admin=true;" in plain_text


def c14():
    unknown_key = get_random_bytes(16)
#    oracle = lambda pt: c14_encryption_oracle(unknown_key, pt)

    def oracle(pt):
        return c14_encryption_oracle(unknown_key, pt)

    block_size = 16

    pad_char = b'A'

    recovered_plain_text = bytearray()
    chosen_plain_text = bytearray()
    while True:

        # We construct a (block_size - 1) piece plain text. Which
        # ends in the our recovered plain text and is prepended with enough
        # pad_char to make the size
        chosen_plain_text[:] = recovered_plain_text
        if len(chosen_plain_text) > block_size - 1:
                chosen_plain_text = chosen_plain_text[-(block_size - 1):]

        added_pad = max(0, (block_size - 1) - len(chosen_plain_text))
        chosen_plain_text = bytearray(pad_char * added_pad) + chosen_plain_text
        assert len(chosen_plain_text) == block_size - 1, "Using correct size chosen_plain_text block"

        # By prepending with enough pad_chars and appending with bytes 0->255,
        # and repeating until we get block_size different
        # answers, we find 'block_size' candidate cipher blocks for each possible end byte
        dictionary = c14_dictionary_for_block(oracle, block_size, chosen_plain_text)

        next_byte = None
        for num_attempts in range(0, 10*block_size):
            pad = pad_char * added_pad
            cipher_text = oracle(pad)
            for c in chunk(cipher_text, block_size):
                try:
                    next_byte = dictionary[c]
                    break
                except KeyError:
                    pass

        if next_byte is None:
            raise RuntimeError("Failed to find next byte in {} iterations", num_attempts)

        recovered_plain_text.append(next_byte)
        print("{}".format(recovered_plain_text.decode('ascii')))

    print("S2C14 msg is {}", recovered_plain_text)


# def c14():
#
#    unknown_key = get_random_bytes(16)
#    oracle = lambda pt: c14_encryption_oracle(unknown_key, pt)
#
#    # Shim is number of bytes to fill a block
#    block_size = c14_discover_block_size(oracle)
#    print("S2C14 - found block size {}".format(block_size))
#
#    is_ecb = c12_detect_ecb(oracle, block_size)
#    print("S2C14 - is ECB?:  {}".format(is_ecb))
#
#    known_bytes = bytearray()
#    for index in range(0, 10 * block_size):
#        print("JB - index {}".format(index))
#        block_index = index // block_size
#        chunk_index = index % block_size
#
#        needed_pad_len = (block_size - 1) - chunk_index
#        needed_pad = bytes(needed_pad_len)
#
#        trick_block = bytearray(block_size) + known_bytes
#        trick_block = trick_block[-(block_size-1):]
#
#        block_dictionary = c14_make_block_dictionary(oracle, block_size, trick_block)
#        cipher_text = oracle(needed_pad)
#
#        cipher_chunks = chunk(cipher_text, block_size)
#        interesting_chunk = cipher_chunks[index // block_size]
#        try:
#            plain_text_byte = block_dictionary[interesting_chunk]
#        except KeyError:
#            break
#
#        known_bytes.append(plain_text_byte)
#
#    print("S2C14 - got msg len: {}".format(len(known_bytes)))
#    plain_text = pkcs7_unpad(known_bytes, block_size)
#    print("S2C14 - got msg: {}".format(plain_text.decode('ascii')))


def c14_discover_block_size(oracle):

    lengths = set()
    for shim_size in range(1, 1000):
        ct = oracle(bytes(shim_size))
        lengths.add(len(ct))

    min_diff = 1000
    last_length = 0
    for length in sorted(lengths):
        if last_length == 0:
            last_length = length
            continue
        diff = length - last_length
        if diff < min_diff:
            min_diff = diff

    return min_diff


def c14_dictionary_for_block(oracle, block_size, chosen_plain_text):
    assert len(chosen_plain_text) == block_size - 1, "Using correct size chosen_plain_text block"

    dictionary = dict()
    duplicates = set()
    enough_padding_for_duplicates = b'_' * ((3 * block_size) - 1)
    for end_byte in range(0, 256):

        plain_text = bytearray(enough_padding_for_duplicates)
        plain_text += chosen_plain_text
        plain_text.append(end_byte)

        candidates = set()
        # Keep trying so we get different offsets
        while len(candidates) < block_size:
            cipher_text = oracle(plain_text)
            candidate = find_block_after_duplicates(cipher_text, block_size)
            candidates.add(candidate)

        for candidate in candidates:
            if candidate in duplicates:
                continue
            if candidate in dictionary:
                duplicates.add(candidate)
                del(dictionary[candidate])
                continue
            dictionary[candidate] = end_byte

    return dictionary


def find_block_after_duplicates(buf, block_size):
    next_is_target = False
    last_chunk = b''

    chunks = chunk(buf, block_size)
    for c in chunks:
        # Continue while we keep seeing duplicates
        if c == last_chunk:
            next_is_target = True
            continue
        if next_is_target:
            return c
        last_chunk = c

    raise RuntimeError("Didn't find block after duplicates")


def c14_encryption_oracle(key, chosen_plain_text):
    block_size = 16

    secret_suffix = b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK""")
    prefix_size = randrange(20, 40)
    random_prefix = get_random_bytes(prefix_size)
    msg = random_prefix + chosen_plain_text + secret_suffix
#    chunk_index = 0
#    chunks = chunk(msg, 16)
#    for c in chunks:
#        chunk_index+= 1
#        print("JB - oracle pt {}/{}: [{}]".format(chunk_index, len(chunks), c))
    msg = pkcs7_pad(msg, block_size)

    return aes128_ecb_encode(key, msg)


def c13():
    block_size = 16
    secret_key = get_random_bytes(block_size)

    def encryptor(email_address):
        return aes128_ecb_encode(secret_key, pkcs7_pad(c13_profile_for(email_address), block_size))

    def decryptor(cipher_text):
        return c13_parse_kv(pkcs7_unpad(aes128_ecb_decode(secret_key, cipher_text), block_size))

    # The minimum amount of prefix padding to cause a duplicated block
    # will give us the target block in the next block
    for repeat_pad_size in range(2*block_size - 1, 3 * block_size):
        repeat_pad = b"A" * repeat_pad_size
        trick_email_address = repeat_pad + pkcs7_pad(b"admin", block_size) + b"@example.com"
        cipher_text = encryptor(trick_email_address)

        chunks = chunk(cipher_text, block_size)
        # If we have a repeat, the block after repeat is target
        next_is_target = False
        target_cipher_block = b''
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
    for padding_size in range(0, block_size):
        padded_email_address = (b"A" * padding_size) + b"@example.com"

        cipher_text = encryptor(padded_email_address)
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

    print("S2C13 fail. Bad coder, no biscuit")


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

    def oracle(pt):
        return c12_encryption_oracle(unknown_key, pt)

    # Shim is number of bytes to fill a block
    (block_size, shim_size) = c12_discover_block_and_shim_sizes(oracle)
    print("S2C12 - found block size {}".format(block_size))

    is_ecb = c12_detect_ecb(oracle, block_size)
    print("S2C12 - is ECB?:  {}".format(is_ecb))

    known_bytes = bytearray()

    for index in range(0, 10 * block_size):
        #        block_index = index // block_size
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

    max_block_size = 1000

    zero_len = len(oracle(b''))
    for shim_size in range(1, max_block_size):
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
    block_size = 16     # we're doing AES128
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

    plain_text = aes128_cbc_decode(key, iv, cipher_text)
    print("S1C10 msg is {}".format(plain_text.decode('ascii')))
    recipher_text = aes128_cbc_encode(key, iv, plain_text)
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
