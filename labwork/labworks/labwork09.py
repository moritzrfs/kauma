

import hashlib
import hmac
import os
import random


def gk_drbg(drbg_key, index):
    # set data to encoded big endiant index
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
    # raw_integer = bytes2integer_big_endian(values)
    raw_integer = int.from_bytes(bytes(values), byteorder='big')
    # mask off the extra bits
    bit_mask = (1 << bitlen) - 1
    # raw_integer &= bit_mask
    raw_integer &= bit_mask
    # raw_integer set_bit(bitlen - 1)
    raw_integer |= (1 << (bitlen - 1))
    return raw_integer

def gk_candprime(drbg_key, bitlen):
    raw_integer = gk_intrg(drbg_key, bitlen)
    raw_integer |= 1
    raw_integer |= (1 << (bitlen - 2))
    return raw_integer

def gk_nextprime(value):
    # value.set_bit(0)
    value |= 1
    while True:
        # if value.is_prime():
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
    # q_bitlen = modulus_bitlen - p.bit_length()
    q_bitlen = modulus_bitlen - p.bit_length()
    while True:
        # n_guess = seed.as_big_endian_integer << (modulus_bitlen - 64)
        n_guess = int.from_bytes(seed, byteorder='big') << (modulus_bitlen - 64)
        # n_guess += random_integer(0, 1 << (modulus_bitlen - 64))
        n_guess += gk_intrg(seed, modulus_bitlen - 64)
        q_start = n_guess // p
        q = gk_nextprime(q_start)
        n = p * q
        # if n.topmost_64_bits() == seed
        if n >> (modulus_bitlen - 64) == int.from_bytes(seed, byteorder='big'):
            return q

def gk_derive_drbg_key(agency_key, seed):
    assert(isinstance(seed, bytes))
    assert(len(seed) == 8)
    # return sha256_digest(agency_key + seed)
    return hashlib.sha256(agency_key + seed).digest()

def gk_p_from_seed(agency_key, seed, modulus_bitlen):
    # drbg_key = gk_derive_drbg_key(agency_key, seed)
    drbg_key = gk_derive_drbg_key(agency_key, seed)
    p = gk_pgen(drbg_key, modulus_bitlen)
    return p

def gk_rsakey_from_seed(agency_key, seed, modulus_bitlen):
    e = 65537
    p = gk_p_from_seed(agency_key, seed, modulus_bitlen)
    q = gk_qgen(seed, modulus_bitlen, p)
    # (n, phi_n) = compute_preliminary_rsa_key(p, q)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    # d = modular_inverse(e, phi_n)
    if gcd(phi_n, e) != 1:
        return None
    d = pow(e, -1, phi_n)
    return(p, q, n, d, e)

def gk_rsa_gen(agency_key, modulus_bitlen):
    while True:
        seed = os.urandom(8)
        # seed.set_bit(63)
        seed |= (1 << 63)
        rsa_key = gk_rsakey_from_seed(agency_key, seed, modulus_bitlen)
        if rsa_key is not None:
            return rsa_key

def gk_rsa_escrow(agency_key, n):
    #seed = n.extract_topmost_bits(64).as_big_endian_bytes()
    seed = n >> (n.bit_length() - 64)
    e = 65537
    # p = gk_p_from_seed(agency_key, seed, modulus_bitlen)
    p = gk_p_from_seed(agency_key, seed.to_bytes(8, byteorder='big'), n.bit_length())
    assert((n % p) == 0)
    q = n // p
    return(p, q)


def is_Prime(n):
    """
    Miller-Rabin primality test.

    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
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

# helper function to compute the greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

drbg_key = bytes.fromhex("486173736c65686f6666")
agency_key = bytes.fromhex("7472757374207573")

# assert(gk_drbg(drbg_key, 0) == 0xe0)
# assert(gk_drbg(drbg_key, 1) == 0x8b)
# assert(gk_drbg(drbg_key, 2) == 0x6a)
# assert(gk_drbg(drbg_key, 3) == 0x1a)
# assert(gk_drbg(drbg_key, 4) == 0x98)
# assert(gk_primerg(drbg_key, 32) == 3767233061)
# assert(gk_primerg(drbg_key, 48) == 246889385203807)
# assert(gk_primerg(drbg_key, 64) == 16180142748715663259)
# assert(gk_pgen(drbg_key, 64) == 3767233061)
# assert(gk_pgen(drbg_key, 65) == 3767233061)

assert(gk_p_from_seed(agency_key, bytes.fromhex("80 11 22 33 44 55 66 77"), 128) == 17618103176262747533)