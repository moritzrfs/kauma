
import base64
import hashlib
from math import gcd

assignment_test = {
        "msg": "TmV2ZXIgZ29ubmEgZ2l2ZSB5b3UgdXAsIG5ldmVyIGdvbm5hIGxldCB5b3UgZG93biwgbmV2ZXIgZ29ubmEgcnVuIGFyb3VuZCBhbmQgZGVzZXJ0IHlvdSA4NTc3MDY5MzgyOTcwMzMwNDky",
        "pubkey": {
          "e": "WrGEmdpYU21BjQWTbJCoT/fqjSSW0qBYjz6dWEUOHLE=",
          "n": "rfKLSVnKBW93tFLKsfeNPxJ0ojPkWQbHIodYL4WKwKE="
        },
        "sigs": [
          "K8m9TFrGtnAsvcujb0iPa9Unewnj+dqok4DtcVrFOI4=",
          "Etx9vrQAmbsOT2YGVTFO/8elSR4CRCRjjBizHFpSqO8="
        ]
      }

def handle_rsa_crt_fault_injection(assignment):
    msg = b64_to_int(assignment['msg'])
    e = b64_to_int(assignment['pubkey']['e'])
    n = b64_to_int(assignment['pubkey']['n'])
    s_1 = b64_to_int(assignment['sigs'][0])
    s_2 = b64_to_int(assignment['sigs'][1])

    c_s_1 = (get_signature(s_1, e, n))
    c_s_2 = (get_signature(s_2, e, n))
    print(int_to_bytes(c_s_1))
    print(int_to_bytes(c_s_2))

def b64_to_int(b64):
    '''
    Convert a base64 encoded string to an integer
    with big endian byte order (most significant byte first)
    with length of 100 bytes
    '''
    return int.from_bytes(base64.b64decode(b64), byteorder='big')

def factor_n(s1, e, m1, N):
    p = gcd(s1^e - m1, N)
    return p

def check_signature(msg, sig, e, n):
    print(((sig^e) % n ))
    print((msg % n))
    return ((sig^e) % n ) == (msg % n)

def get_signature(s, e, n):
    return (s^e) % n

def int_to_bytes(i):
    '''
    Convert an integer to a byte string with big endian byte order
    (most significant byte first) with leading zeros

    '''
    return i.to_bytes(100, byteorder='big')


handle_rsa_crt_fault_injection(assignment_test)

