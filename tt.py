#!/usr/bin/python3

from base64 import b64encode


def main():
    c3()
    c2()
    c1()


def c3():
    cipher_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipher_text = bytes.fromhex(cipher_hex)
    key_tuple = min([(english_score(xor_byte(cipher_text, i)), i) for i in range(0, 256)], key=lambda t: t[0])
    key_byte = key_tuple[1]
    plain_text = xor_byte(cipher_text, key_byte)
    print ("S1C3 key is {}, msg is {}".format(key_byte, plain_text))


def xor_byte(buf, key):
    return bytes([b ^ key for b in buf])


def english_score(buf):
    expected_order = list(map(lambda c: ord(c), " etaoinshrdlcumwfgypbvkjxqz_"))
    expected_set = set(expected_order)
    # Downcase any letters, then map all non-alphaspace to '_'
    mapped_buf = list(map(lambda b: b if b in expected_set else ord('_'), map(lambda c: c | 0x20, buf)))

    counts = dict(map(lambda b: (b, mapped_buf.count(b)), mapped_buf))
    return 1.0


def c2():
    a_hex = "1c0111001f010100061a024b53535009181c"
    a = bytes.fromhex(a_hex)
    b_hex = "686974207468652062756c6c277320657965"
    b = bytes.fromhex(b_hex)

    x = xor_buf(a, b)

    expected_hex = "746865206b696420646f6e277420706c6179"
    expected = bytes.fromhex(expected_hex)

    print ("S1C2 - got {} expected {}: {}".format(x, expected, x == expected))


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
else:
    throw("Not a lib")

