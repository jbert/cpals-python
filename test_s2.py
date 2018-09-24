from s2 import c13_parse_kv, c13_profile_for, find_block_after_duplicates


def test_c13_parse_kv():
    assert c13_parse_kv(b'foo=bar&baz=qux&zap=zazzle') == {b"foo": b"bar", b"baz": b"qux", b"zap": b"zazzle"}


def test_c13_profile_for():
    assert c13_profile_for(b'foo@example.com') == b"email=foo@example.com&uid=10&role=user"
    assert c13_profile_for(b'foo=bar@example.com') == b"email=foobar@example.com&uid=10&role=user"
    assert c13_profile_for(b'foo&bar@example.com') == b"email=foobar@example.com&uid=10&role=user"


def test_find_block_after_duplicates():
    testcases = [
            (b"aaababac", 2, b"ac"),
            (b"aaababacad", 2, b"ac"),
            (b"aaabababacad", 2, b"ac"),
            ]
    for testcase in testcases:
        (buf, block_size, expected) = testcase
        actual = find_block_after_duplicates(buf, block_size)
        assert actual == expected, "'{}' size {} {} != {}".format(buf, block_size, expected, actual)
