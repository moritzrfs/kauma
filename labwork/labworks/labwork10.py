import base64

"""Domain Parameters for the given curve"""
a = 3
b = 0xC2660DC9F6F5E79FD5CCC80BDACF5361870469B61646B05EFE3C96C38FF96BAD
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
G = (8, 0x22CE834ED9C6D4500E9FB042A6D6E66E98B46743387396C321FE7CE5164888D)
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFE8F4E0793DE3B9C2E0F61060A88B13657
h = 1


def scalar_mult(k, P):
    """
    Scalar multiplication of a point P by a scalar k
    """
    if k == 0 or P == (0, 0):
        return (0, 0)
    Q = P
    R = (0, 0)
    while k:
        if k & 1:
            R = add_points(R, Q)
        Q = add_points(Q, Q)
        k >>= 1
    return R


def add_points(P, Q):
    """
    Add two points P and Q on the elliptic curve
    """
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    x_1, y_1 = P
    x_2, y_2 = Q
    if x_1 == x_2 and y_1 != y_2:
        return (0, 0)
    if x_1 == x_2:
        m = (3 * x_1 * x_1 + a) * inverse_mod(2 * y_1, p)
    else:
        m = (y_1 - y_2) * inverse_mod(x_1 - x_2, p)
    x_3 = m * m - x_1 - x_2
    y_3 = y_1 + m * (x_3 - x_1)
    return (x_3 % p, -y_3 % p)


def inverse_mod(k, p):
    """
    Returns the inverse of k modulo p.
    """
    if k >= 0:
        s, pre_s = 0, 1
        t, pre_t = 1, 0
        r, pre_r = p, k
        while r != 0:
            quotient = pre_r // r
            pre_r, r = r, pre_r - quotient * r
            pre_s, s = s, pre_s - quotient * s
            pre_t, t = t, pre_t - quotient * t
        return pre_s % p
    else:
        return p - inverse_mod(-k, p)


def truncate(r, bits):
    """
    Truncate r to the given number of bits
    """
    return r & ((1 << bits) - 1)


def get_next(backdoorkey, drgb_output, outbits, P, Q):
    """
    Get the next number from the given output of the DRBG
    """
    inverse = inverse_mod(backdoorkey, n)
    for bits in range(0x10000):
        bits <<= 248
        possible_x = bits | drgb_output[0]
        possible_point = (
            possible_x,
            pow(possible_x**3 + a * possible_x + b, (p + 1) // 4, p),
        )
        possible_t = scalar_mult(inverse, possible_point)[0]
        r = truncate(scalar_mult(possible_t, Q)[0], outbits)

        if r == drgb_output[1]:
            found = True
            for do in drgb_output[2:]:
                possible_t = scalar_mult(possible_t, P)[0]
                r = truncate(scalar_mult(possible_t, Q)[0], outbits)
                if r != do:
                    found = False

            if found:
                t = scalar_mult(possible_t, P)[0]
                r = truncate(scalar_mult(t, Q)[0], outbits)
                return r


def handle_dual_ec_dbrg(assignment):
    """
    Handle the dual EC DRBG assignment
    """
    P_bytes = base64.b64decode(assignment["P"])
    P_x_int = int.from_bytes(P_bytes[1:33], byteorder="big")
    P_y_int = int.from_bytes(P_bytes[33:], byteorder="big")
    P = (P_x_int, P_y_int)

    Q_bytes = base64.b64decode(assignment["Q"])
    Q_x_int = int.from_bytes(Q_bytes[1:33], byteorder="big")
    Q_y_int = int.from_bytes(Q_bytes[33:], byteorder="big")
    Q = (Q_x_int, Q_y_int)

    backdoorkey_int = int.from_bytes(
        base64.b64decode(assignment["backdoor_key"]), byteorder="big"
    )
    dbrg_output_bytes = base64.b64decode(assignment["dbrg_output"])
    outbits_int = assignment["outbits"]

    blocks_bytes = [
        dbrg_output_bytes[i : i + 31] for i in range(0, len(dbrg_output_bytes), 31)
    ]
    blocks_int = [int.from_bytes(block, byteorder="big") for block in blocks_bytes]

    next_int = get_next(backdoorkey_int, blocks_int, outbits_int, P, Q)
    next_bytes = next_int.to_bytes((next_int.bit_length() + 7) // 8, "big")
    next_b64 = base64.b64encode(next_bytes).decode("utf-8")

    return {"next": next_b64}
