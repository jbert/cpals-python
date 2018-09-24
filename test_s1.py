from s1 import hamming_distance


def test_hamming_distance():
    assert(hamming_distance(b"this is a test", b"wokka wokka!!!") == 37)
    assert(hamming_distance(b"000000", b"000001") == 1)
    assert(hamming_distance(b"000000", b"000003") == 2)
