import random

'''
generates a key with length of 256 bytes that, if applied
to the given sbox, will result in the original sbox. This
is done by following the method to have i = j since they
are exchanged in the end of the ksa.
'''
def rc4_bonus(s: list): 
    key = bytearray(256)
    for i in range(256):
        key[i] = (1 + (256 - s[i])) % 256
        if i==0: key[i] -= 1
    return key

def handle_ksa(key: bytes, s: list):
    j = 0
    for i in range(0, len(key)):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def generate_random_sbox():
    s = [i for i in range(256)]
    random.shuffle(s)
    return s

'''
Sbox pre: [0, 1, 2, ..., 255]
Sbox post: [0, 1, 2, ..., 255]
Used key:
[0, 0, 255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240, 239, 238, 237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226, 225, 224, 223, 222, 221, 220, 219, 218, 217, 216, 215, 214, 213, 212, 211, 210, 209, 208, 207, 206, 205, 204, 203, 202, 201, 200, 199, 198, 197, 196, 195, 194, 193, 192, 191, 190, 189, 188, 187, 186, 185, 184, 183, 182, 181, 180, 179, 178, 177, 176, 175, 174, 173, 172, 171, 170, 169, 168, 167, 166, 165, 164, 163, 162, 161, 160, 159, 158, 157, 156, 155, 154, 153, 152, 151, 150, 149, 148, 147, 146, 145, 144, 143, 142, 141, 140, 139, 138, 137, 136, 135, 134, 133, 132, 131, 130, 129, 128, 127, 126, 125, 124, 123, 122, 121, 120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102, 101, 100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84, 83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68, 67, 66, 65, 64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2]
'''

sbox_pre = [ i for i in range(256)]
print("Sbox pre:\n", sbox_pre)
key = rc4_bonus(sbox_pre)
sbox_post = handle_ksa(key, sbox_pre)
print("Sbox post:\n", sbox_post)