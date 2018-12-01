from s3 import MersenneTwister


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
