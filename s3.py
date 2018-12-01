#!/usr/bin/python3
from random import choice
from util import pkcs7_pad, pkcs7_unpad, chunk, get_random_bytes, transpose
from s2 import aes128_cbc_encode, aes128_cbc_decode, aes128_ecb_encode
from s1 import c4_best_single_byte_xor, xor_buf
from base64 import b64decode
from itertools import count, chain, repeat
from time import time, sleep
from random import randrange


def main():
    c22()


def c22():
    now = int(time())
    mt = MersenneTwister()
    mt.seed(now)

    sleep_secs = randrange(2, 7)
    print("Sleeping for {} seconds".format(sleep_secs))
    sleep(sleep_secs)

    val = mt.genrand_int32()

    guessed_seed = guess_recent_time_seed(val)
    print("seed {} guess {} gotit {}".format(now, guessed_seed, guessed_seed == now))


def guess_recent_time_seed(v):
    now = int(time())
    for delta in range(0, 100):
        seed = now - delta
        mt = MersenneTwister()
        mt.seed(seed)
        if mt.genrand_int32() == v:
            return seed

    raise RuntimeError("Didn't find it")


def c21():

    mt = MersenneTwister()
    mt.seed(0)
    for i in range(0, 10):
        print(mt.genrand_int32())

class MersenneTwister():

    def __init__(self):

        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = 0x9908B0DF
        self.u = 11
        self.d = 0xFFFFFFFF
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.f = 1812433253

        self.mt = list(repeat(0, self.n))

        self.index = self.n + 1

    def seed_from_state(self, state):
        if len(state) != self.n:
            raise RuntimeError("Invalid state size: {}", len(state))

        self.mt = state
        self.index = 0

    def seed(self, seed):
        self.index = self.n
        self.mt[0] = seed
        for i in range(1, self.n):
            # Truncate to 32bit
            self.mt[i] = (self.f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i) & self.d

    def genrand_int32(self):
        if self.index >= self.n:
            if self.index > self.n:
                # Alternatively, seed with constant value; 5489 is used in reference C code[46]
                raise RuntimeError("Generator was never seeded")

            self.twist()

        y = self.mt[self.index]
        self.index = self.index + 1;
        return self.temper(y)

    def genrand_buf(self, length):
        return [self.genrand_int32() for _ in range(0, length)]

    def temper(self, y):
        y = self.rshift(y, self.u, self.d)
        y = self.lshift(y, self.s, self.b)
        y = self.lshift(y, self.t, self.c)
        y = self.rshift(y, self.l, 0xffffffff)

        return y

    def untemper(self, y):
        y = self.invert_rshift(y, self.l, 0xffffffff)
        y = self.invert_lshift(y, self.t, self.c)
        y = self.invert_lshift(y, self.s, self.b)
        y = self.invert_rshift(y, self.u, self.d)

        return y

    def rshift(self, y, num_bits, mask):
        return y ^ ((y >> num_bits) & mask)

    def lshift(self, y, num_bits, mask):
        return y ^ ((y << num_bits) & mask)

    def invert_rshift(self, y, num_bits, mask):
        read_bitmask = 1 << 31;
        write_bitmask = read_bitmask >> num_bits;
        while write_bitmask > 0:
            bit = y & read_bitmask
            if bit != 0:
                y = y ^ write_bitmask & mask

            read_bitmask = read_bitmask >> 1
            write_bitmask = write_bitmask >> 1
        return y

    def invert_lshift(self, y, num_bits, mask):
        read_bitmask = 1
        write_bitmask = read_bitmask << num_bits
        while write_bitmask > 0:
            bit = y & read_bitmask
            if bit != 0:
                y = y ^ write_bitmask & mask

            read_bitmask = read_bitmask << 1
            write_bitmask = write_bitmask << 1
        return y

    def twist(self):
        lower_mask = (1 << self.r) - 1
        upper_mask = lower_mask ^ 0xffffffff
        for i in range(0, self.n):
            x = (self.mt[i] & upper_mask) + ((self.mt[(i + 1) % self.n]) & lower_mask)
            x_a = x >> 1
            if x % 2 != 0:
                x_a = x_a ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ x_a
        self.index = 0;

def c19():
    b64_cipher_texts = [
            b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
            b'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
            b'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
            b'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
            b'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
            b'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
            b'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
            b'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
            b'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
            b'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
            b'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
            b'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
            b'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
            b'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
            b'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
            b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
            b'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
            b'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
            b'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
            b'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
            b'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
            b'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
            b'U2hlIHJvZGUgdG8gaGFycmllcnM/',
            b'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
            b'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
            b'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
            b'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
            b'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
            b'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
            b'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
            b'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
            b'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
            b'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
            b'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
            b'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
            b'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
            b'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
            b'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
            b'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
            b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
            ]


    block_size = 16
    random_key = get_random_bytes(block_size)
    reused_nonce = 0
    def c19_cryptor(plain_text):
        return aes128_ctr_encode(random_key, reused_nonce, plain_text)

    cipher_texts = [b64decode(s) for s in b64_cipher_texts]
    repeat_length = min(map(len, cipher_texts))
    repeated_xor = b''.join(s[0:repeat_length] for s in cipher_texts)
    chunks = [ct[0:repeat_length] for ct in cipher_texts]
    chunks = transpose(chunks)
    keystream = bytes(map(lambda t: t[1], map(c4_best_single_byte_xor, chunks)))
    for ct in cipher_texts:
        ctt = ct[0:repeat_length]
        print(xor_buf(ctt, keystream))


def c18():
    b64_cipher_text = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    cipher_text = b64decode(b64_cipher_text)
    key = b'YELLOW SUBMARINE'
    nonce = 0
    print("S3C18: {}".format(aes128_ctr(key, nonce, cipher_text)))


def aes128_ctr(key, nonce, inbuf):

    def ctr_chunk(t):
        block_count, nonce = t
        return nonce.to_bytes(8, byteorder='little') + block_count.to_bytes(8, byteorder='little')

    # Use map since it allows us to use a lazy inf iterator
    ctr_chunks = map(ctr_chunk, enumerate(repeat(nonce)))
    key_stream_chunks = map(lambda chunk: aes128_ecb_encode(key, chunk), ctr_chunks)
    key_stream = chain.from_iterable(key_stream_chunks)     # Stackoverflow cargo cult
    return bytes([ t[0] ^ t[1] for t in zip(inbuf, key_stream) ])

def aes128_ctr_encode(key, nonce, plain_text):
    return aes128_ctr(key, nonce, plain_text)

def aes128_ctr_decode(key, nonce, cipher_text):
    return aes128_ctr(key, nonce, cipher_text)


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
