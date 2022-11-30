

import base64
import hashlib
import hmac
import os
import random

def gk_drbg(drbg_key, index):
    data = index.to_bytes(4, byteorder='big')
    mic = hmac.new(drbg_key, data, hashlib.sha256).digest()
    return mic[0]

def gk_intrg(drbg_key, bitlen):
    values = []
    if (bitlen % 8) != 0:
        byte_count = (bitlen + 7) // 8
    else:
        byte_count = bitlen // 8
    
    for i in range(byte_count):
        values.append(gk_drbg(drbg_key, i))
    raw_integer = int.from_bytes(bytes(values), byteorder='big')
    bit_mask = (1 << bitlen) - 1
    raw_integer &= bit_mask
    raw_integer |= (1 << (bitlen - 1))
    return raw_integer

def gk_candprime(drbg_key, bitlen):
    raw_integer = gk_intrg(drbg_key, bitlen)
    raw_integer |= 1
    raw_integer |= (1 << (bitlen - 2))
    return raw_integer

def gk_nextprime(value):
    value |= 1
    while True:
        if is_Prime(value):
            return value
        value += 2

def gk_primerg(drbg_key, bitlen):
    candidate = gk_candprime(drbg_key, bitlen)
    return gk_nextprime(candidate)
    
def gk_pgen(drbg_key, modulus_bitlen):
    p_bitlen = modulus_bitlen // 2
    return gk_primerg(drbg_key, p_bitlen)

def gk_qgen(seed, modulus_bitlen, p):
    assert(isinstance(seed, bytes))
    assert(len(seed) == 8)
    q_bitlen = modulus_bitlen - p.bit_length()
    while True:
        n_guess = int.from_bytes(seed, byteorder='big') << (modulus_bitlen - 64)
        n_guess += gk_intrg(seed, modulus_bitlen - 64)
        q_start = n_guess // p
        q = gk_nextprime(q_start)
        n = p * q
        if n >> (modulus_bitlen - 64) == int.from_bytes(seed, byteorder='big'):
            return q

def gk_derive_drbg_key(agency_key, seed):
    assert(isinstance(seed, bytes))
    assert(len(seed) == 8)
    return hashlib.sha256(agency_key + seed).digest()

def gk_p_from_seed(agency_key, seed, modulus_bitlen):
    drbg_key = gk_derive_drbg_key(agency_key, seed)
    p = gk_pgen(drbg_key, modulus_bitlen)
    return p

def gk_rsakey_from_seed(agency_key, seed, modulus_bitlen, e=65537):
    p = gk_p_from_seed(agency_key, seed, modulus_bitlen)
    q = gk_qgen(seed, modulus_bitlen, p)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    if gcd(phi_n, e) != 1:
        return None
    d = pow(e, -1, phi_n)
    return(p, q, n, d, e)

def gk_rsa_gen(agency_key, modulus_bitlen, e=65537):
    while True:
        seed = os.urandom(8)
        seed |= (1 << 63)
        rsa_key = gk_rsakey_from_seed(agency_key, seed, modulus_bitlen, e)
        if rsa_key is not None:
            return rsa_key

def gk_rsa_escrow(agency_key, n, e):
    seed = n >> (n.bit_length() - 64)
    p = gk_p_from_seed(agency_key, seed.to_bytes(8, byteorder='big'), n.bit_length())
    assert((n % p) == 0)
    q = n // p
    return(p, q)

def is_Prime(n):
    """
    Miller-Rabin primality test
    """

    if n!=int(n):
        return False
    n=int(n)
    #Miller-Rabin test for prime
    if n==0 or n==1 or n==4 or n==6 or n==8 or n==9:
        return False
        
    if n==2 or n==3 or n==5 or n==7:
        return True
    s = 0
    d = n-1
    while d%2==0:
        d>>=1
        s+=1
    assert(2**s * d == n-1)
  
    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True  
 
    for i in range(8):#number of trials 
        a = random.randrange(2, n)
        if trial_composite(a):
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def handle_glasskey(assignment):
    agency_key = base64.b64decode(assignment['agency_key'])
    n = int.from_bytes(base64.b64decode(assignment['n']), byteorder='big')
    e = assignment['e']
    p, q = gk_rsa_escrow(agency_key, n, e)
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    d = base64.b64encode(d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
    print({'d': d})
    return {'d': d}