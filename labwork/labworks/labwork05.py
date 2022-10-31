import base64
import sys

# API_ENDPOINT = sys.argv[1]

def iv_string_handle(iv_dump) -> list[bytes]:
    iv_dump = base64.b64decode(iv_dump)
    iv_dumps = [iv_dump[i:i+4] for i in range(0, len(iv_dump), 4)]
    return iv_dumps

def handle_ksa(key: hex, key_length: int) -> list[int]:
    key = key.to_bytes(key_length, byteorder='big')
    s = [i for i in range(256)]
    j = 0
    for i in range(0, 255):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def handle_prga(s: list, key_length: int) -> list:
    i = j = 0
    keystream = []
    for _ in range(key_length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        keystream.append(s[(s[i] + s[j]) % 256])
    return keystream

def handle_keystream(key_length: int, key: hex) -> list[int]:
    s = handle_ksa(key, key_length)
    keystream = handle_prga(s , key_length)
    return keystream

def convert_list_to_hex(keystream: list[int]) -> list[str]:
    keystream_hex = [hex(i) for i in keystream]
    return keystream_hex