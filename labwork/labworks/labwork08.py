
import base64
import hashlib
from math import gcd
import hashlib

def handle_rsa_crt_fault_injection(assignment):
    msg = base64.b64decode(assignment['msg'])
    e = b64_to_int(assignment['pubkey']['e'])
    n = b64_to_int(assignment['pubkey']['n'])
    sigs = [b64_to_int(sig) for sig in assignment['sigs']]
    invalid_s, m = get_invalid_signature(sigs, e, n, msg)
    prime = factor_n(invalid_s, e, m, n)
    p = min(prime, n // prime)
    q = n // p
    d = pow(e, -1, (p - 1) * (q - 1))
    return {
        'd': base64.b64encode(int_to_bytes(d)).decode(),
        'p': base64.b64encode(int_to_bytes(p)).decode(),
        'q': base64.b64encode(int_to_bytes(q)).decode()
    }

def b64_to_int(b64):
    return int.from_bytes(base64.b64decode(b64), byteorder='big')

def factor_n(s, e, m, n):
    p = gcd((pow(s, e, n) - m) % n, n)
    return p

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def get_invalid_signature(sigs, e, n, msg):
    m = 0
    m_hash = hashlib.md5(msg).digest()
    for sig in sigs:
        s_bytes =  int_to_bytes(pow(sig, e, n))        
        if m_hash not in s_bytes:
            s = sig
        elif m_hash in s_bytes:
            m = int.from_bytes(s_bytes, byteorder='big')
    return s, m
