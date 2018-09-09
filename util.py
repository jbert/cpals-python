__all__ = [ 'pkcs7_pad', 'pkcs7_unpad', 'transpose', 'hex2bytes', 'chunk', 'slurp_base64_file', 'slurp_hex_file_as_lines' ]

from base64 import b64decode
import itertools

def pkcs7_unpad(buf, block_size):
    raise RuntimeError("pkcs7_unpad: bad padding")

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
