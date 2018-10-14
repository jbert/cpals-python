import pytest
from util import chunk, transpose, pkcs7_unpad, hexquote_chars


def test_hexquote_chars():
    assert(hexquote_chars(b"", b"ice ice baby") == b"ice ice baby")
    assert(hexquote_chars(b"i", b"ice ice baby") == b"%69ce %69ce baby")


def test_chunk():
    s = "abcdefghij"
    assert(chunk(s, 2) == ['ab', 'cd', 'ef', 'gh', 'ij'])
    assert(chunk(s, 3) == ['abc', 'def', 'ghi', 'j'])
    assert(chunk(s, 4) == ['abcd', 'efgh', 'ij'])
    assert(chunk(s, 5) == ['abcde', 'fghij'])


def test_transpose():
    chunks = [b'123', b'456']
    assert(transpose(chunks) == [b'14', b'25', b'36'])
    chunks = [b'123', b'456', b'7']
    assert(transpose(chunks) == [b'147', b'25', b'36'])


def test_pkcs7_unpad():
    block_size = 16
    assert(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", block_size) == b"ICE ICE BABY")
    with pytest.raises(RuntimeError) as e_info:
        pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", block_size) 
    with pytest.raises(RuntimeError) as e_info:
        pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", block_size) 
    with pytest.raises(RuntimeError) as e_info:
        pkcs7_unpad(b"ICE ICE BABY\x01", block_size) 
