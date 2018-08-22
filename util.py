__all__ = [ 'hex2bytes' ]

def hex2bytes(hex_str):
    s = "".join(hex_str.split())
    return bytes.fromhex(s)

