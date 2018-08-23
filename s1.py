#!/usr/bin/python3

from base64 import b64encode
from util import *
import itertools


def main():
    c5()
#    c4()
#    c3()
#    c2()
#    c1()


def encrypt_xor(plain_text, key):
    key_iter = itertools.cycle(key)
    return bytes(map(lambda b: b ^ next(key_iter), plain_text))


def c5():
    plain_text = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key = b"ICE"
    cipher_text = encrypt_xor(plain_text, key)
    print("JB - pt is [{}]".format(plain_text))
    expected_hex = """0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"""
    expected = hex2bytes(expected_hex)
    print("S1C5 - cipher_text is [{}]: correct {}".format(cipher_text.hex(), expected == cipher_text))


def c4():
    with open("4.txt") as f:
        lines = f.readlines()

    c4_tuple = max(map(c4_best_single_byte_xor, map(hex2bytes, lines)))
    print("S1C4 - c4_tuple {}".format(c4_tuple))


def c4_best_single_byte_xor(buf):
#    key_tuple = max([(english_score(xor_byte(buf, i)), i) for i in range(0, 256)], key=lambda t: t[0])
    key_tuple = max([(english_score(xor_byte(buf, i)), i) for i in range(0, 256)])
    key_score = key_tuple[0]
    key_byte = key_tuple[1]
    plain_text = xor_byte(buf, key_byte)
    return (key_score, key_byte, plain_text)


def c3():
    cipher_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipher_text = bytes.fromhex(cipher_hex)
    key_tuple = max([(english_score(xor_byte(cipher_text, i)), i) for i in range(0, 256)], key=lambda t: t[0])
    key_byte = key_tuple[1]
    plain_text = xor_byte(cipher_text, key_byte)
    print("S1C3 key is {}, msg is {}".format(key_byte, plain_text))


def xor_byte(buf, key):
    return bytes([b ^ key for b in buf])


#def english_score(buf):
#    expected_order = list(map(lambda c: ord(c), " etaoinshrdlcumwfgypbvkjxqz_"))
#    expected_set = set(expected_order)
#    # Downcase any letters, then map all non-alphaspace to '_'
#    mapped_buf = list(map(lambda b: b if b in expected_set else ord('_'), map(lambda c: c | 0x20, buf)))
#
#    counts = dict(map(lambda b: (b, mapped_buf.count(b)), mapped_buf))
#    sorted_counts = sorted(counts.items(), key=lambda byte_count: byte_count[1], reverse=True)
#    order = list(map(lambda byte_count: byte_count[0], sorted_counts))
#
#    distance = 1 + order_distance(expected_order, order)
##    unlikelihood = 0.0
##    for b in mapped_buf:
##        unlikelihood += expected_order.index(b)
#    return 1.0 / distance

def english_score(buf):
    score = 0.0
    tier1 = b"etaoin"
    tier2 = b"shrdlu"

    for b in buf:
        b = b | 0x20    # lowercase
        if b >= ord('a') and b <= ord('z'):
            score += 1;
            if b in tier1:
                score += 2
            elif b in tier2:
                score += 1
        elif b == ord(' '):
            score += 3
        else:
            score += 0

    return score / len(buf)


def c2():
    a_hex = "1c0111001f010100061a024b53535009181c"
    a = bytes.fromhex(a_hex)
    b_hex = "686974207468652062756c6c277320657965"
    b = bytes.fromhex(b_hex)

    x = xor_buf(a, b)

    expected_hex = "746865206b696420646f6e277420706c6179"
    expected = bytes.fromhex(expected_hex)

    print("S1C2 - got {} expected {}: {}".format(x, expected, x == expected))


def xor_buf(a_s, b_s):
    return bytes([a ^ b for (a, b) in zip(a_s, b_s)])


def c1():
    hexstr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    # buf = bytearray.fromhex(hexstr)
    buf = bytes.fromhex(hexstr)
    b64str = b64encode(buf)
    print("S1C1 is {}".format(b64str))


if __name__ == "__main__":
    main()
