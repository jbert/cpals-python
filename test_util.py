from util import chunk, transpose


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
