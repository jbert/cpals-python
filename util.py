__all__ = [ 'transpose', 'hex2bytes', 'chunk', 'slurp_base64_file' ]

from base64 import b64decode

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
