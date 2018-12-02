from s3 import MersenneTwister, mt_ctr


def test_mt_seed():
    mt_a = MersenneTwister()
    mt_a.seed(19650218)
    mt_b = MersenneTwister()
    mt_b.seed(19650218)
    mt_x = MersenneTwister()
    mt_x.seed(1623577)

    num_tests = 100
    for i in range(0, num_tests):
        a = mt_a.genrand_int32()
        b = mt_b.genrand_int32()
        x = mt_x.genrand_int32()
        assert a == b, "Same seed for iteration {} still the same".format(i)
        assert a != x, "Diff seed for iteration {} still the same".format(i)


def test_mt_ctr():
    seed = 1234
    plain_text = b"why hello there"
    cipher_text = mt_ctr(seed, plain_text)
    assert plain_text != cipher_text, "encoding works..."
    decoded_cipher_text = mt_ctr(seed, cipher_text)
    assert decoded_cipher_text == plain_text, "decoding works..."
