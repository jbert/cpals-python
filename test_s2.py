from s2 import c13_parse_kv, c13_profile_for

def test_c13_parse_kv():
    assert(c13_parse_kv(b'foo=bar&baz=qux&zap=zazzle') == { b"foo": b"bar", b"baz": b"qux", b"zap": b"zazzle"})


def test_c13_profile_for():
    assert(c13_profile_for(b'foo@example.com') == b"email=foo@example.com&uid=10&role=user")
    assert(c13_profile_for(b'foo=bar@example.com') == b"email=foobar@example.com&uid=10&role=user")
    assert(c13_profile_for(b'foo&bar@example.com') == b"email=foobar@example.com&uid=10&role=user")


