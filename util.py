__all__ = [
        'get_random_bytes',
        'pkcs7_pad',
        'pkcs7_unpad',
        'transpose',
        'hex2bytes',
        'chunk',
        'slurp_base64_file',
        'slurp_hex_file_as_lines',
        ]

from base64 import b64decode
import itertools
from random import randrange


def hexquote_chars(chars_to_quote, buf):
    for char in chars_to_quote:
        replacement = "%{:02x}".format(char).encode('ascii')
        buf = buf.replace(char.to_bytes(1, byteorder='big'), replacement)
    return buf


def get_random_bytes(size):
    return b''.join(map(lambda x: bytes([randrange(0, 256)]), itertools.repeat(0, size)))


def pkcs7_unpad(buf, block_size):
    print("JB - PU1")
    if len(buf) % block_size != 0:
        raise RuntimeError("pkcs7_unpad: non-block-size input")
    num_to_remove = buf[-1]
    print("JB - PU2: {:02x}".format(num_to_remove))
    if num_to_remove < 1 or num_to_remove > block_size:
        raise RuntimeError("pkcs7_unpad: bad padding value")
    print("JB - PU3")
    for i in range(0, num_to_remove):
        b = buf[-(i+1)]
        if b != num_to_remove:
            raise RuntimeError("pkcs7_unpad: invalid byte at {}: {} != {}".format(i, num_to_remove, b))

    print("JB - PU4")
    return buf[:-num_to_remove]


def pkcs7_pad(buf, block_size):
    chunks = chunk(buf, block_size)
    last_chunk = chunks[-1]
    missing = block_size - len(last_chunk)
    if missing == 0:
        missing = block_size

    addition = bytes(itertools.repeat(missing, missing))
    chunks.append(addition)

    return b''.join(chunks)


def hex2bytes(hex_str):
    s = "".join(hex_str.split())
    return bytes.fromhex(s)


def chunk(buf, size):
    return [buf[i:i+size] for i in range(0, len(buf), size)]


def transpose(chunks):
    chunk_len = len(chunks[0])
    return [bytes(filter(None, map(lambda c: c[i] if len(c) > i else None, chunks))) for i in range(0, chunk_len)]


def slurp_base64_file(fname):
    with open(fname) as f:
        lines = f.readlines()

    return b64decode(''.join(lines))


def slurp_hex_file_as_lines(fname):
    with open(fname) as f:
        lines = f.readlines()

    return list(map(hex2bytes, lines))
