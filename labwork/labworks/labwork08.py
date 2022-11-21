
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
    #print(msg)
    e = b64_to_int(assignment['pubkey']['e'])
    print(e)
    print("+++")
    n = b64_to_int(assignment['pubkey']['n'])
    s1 = b64_to_int(assignment['sigs'][0])
    print(s1)
    s2 = b64_to_int(assignment['sigs'][1])
'''
    p = factor_n(s1, e, m69, n)
    print(p)
    p = factor_n(s2, e, m69, n)
    print(p)'''



def b64_to_int(b64):
    '''
    Convert a base64 encoded string to an integer
    with big endian byte order
    '''
    return int.from_bytes(base64.b64decode(b64), byteorder='big')


def factor_n(s1, e, m1, N):
    p = gcd(s1^e - m1, N)
    return p


def md5(msg):
    '''
    Return the md5 hash of a message.
    '''
    m = hashlib.md5()
    m.update(msg.encode('utf-8'))
    return int(m.hexdigest(), 16)


handle_rsa_crt_fault_injection(assignment_test)