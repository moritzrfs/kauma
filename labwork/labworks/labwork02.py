import base64
import binascii
import itertools
import re
import sys

assignments = {
    "testcases": [
        {
            "tcid": "80dd0cff-975a-4f33-aa83-c6388a838f92",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "AAAAAAAAAAAAAAAAAAAAAA=="
            },
            "expect_solution": {
                "block_times_alpha": "AAAAAAAAAAAAAAAAAAAAAA=="
            }
        },
        {
            "tcid": "b3d95be2-5faa-46fb-8173-0f27304fb98c",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "AQAAAAAAAAAAAAAAAAAAAA=="
            },
            "expect_solution": {
                "block_times_alpha": "AgAAAAAAAAAAAAAAAAAAAA=="
            }
        },
        {
            "tcid": "aa6fa3de-3962-439a-9916-9e61745e5009",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "/////////////////////w=="
            },
            "expect_solution": {
                "block_times_alpha": "ef///////////////////w=="
            }
        },
        {
            "tcid": "ac412ad3-bd61-42ba-b9b6-045feb0c041f",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "PJruhlDOnwyMNVQ/UNZ3ug=="
            },
            "expect_solution": {
                "block_times_alpha": "/zTdDaGcPxkYa6h+oKzvdA=="
            }
        },
        {
            "tcid": "f51dbf5b-a30d-4f15-82af-28e7e7d0b00b",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "DUIJBcf/ImZgq49CtmL2VA=="
            },
            "expect_solution": {
                "block_times_alpha": "GoQSCo7/RczAVh+FbMXsqQ=="
            }
        },
        {
            "tcid": "1edbd141-11d6-48f7-a177-c625df58f5ab",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "AAECAwQFBgcICQoLDA0ODw=="
            },
            "expect_solution": {
                "block_times_alpha": "AAIEBggKDA4QEhQWGBocHg=="
            }
        },
        {
            "tcid": "439e187c-d8b0-443c-b28c-2d4b70a00b26",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "nJKkcBOMP2jJdarwitJrQQ=="
            }
        },
        {
            "tcid": "e39863f1-4801-4700-902e-885f4c65f8e2",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "+LAPKuylWFMATROH0VyHUA=="
            }
        },
        {
            "tcid": "5363bb07-f71b-49e6-8711-1278a8fade03",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "R3WSJjToUcSo2OvnOYu7EQ=="
            }
        },
        {
            "tcid": "2e96fb31-6adf-445a-a987-e49ed8c6a57d",
            "passed_at_utc": "null",
            "type": "mul_gf2_128",
            "assignment": {
                "block": "UNpNIs7GDAbaE6tZ2zrFlw=="
            }
        }
    ]
    }
res_pattern = {
    "at_least_one_special_char" : "[^A-Za-z0-9]+",
    "at_least_one_uppercase_char" : "[A-Z]+",
    "at_least_one_lowercase_char" : "[a-z]+",
    "at_least_one_digit" : "[0-9]+"
}

def find_regex(pattern, alphabet):
    return bool(re.match(pattern, alphabet))

def handle_password_keyspace(assignment):
    password_list= set(itertools.product(assignment['alphabet'], repeat=assignment['length'])) # set of all possible passwords for given alphabet with length
    for restriction in assignment['restrictions']:   # removes all passwords not matching the given patters
        if restriction in res_pattern: 
            for element in password_list.copy():
                lowercase = False
                for c in element:
                    lowercase= find_regex(res_pattern[restriction], c)
                    if lowercase == True:
                        break
                if lowercase == False:
                    password_list.remove(element)
        if restriction == "no_consecutive_same_char":
            for element in password_list.copy():
                s = ''
                for c in element:
                    if c == s:                        
                        password_list.remove(element)
                        break
                    else:
                        s=c
        if restriction == "special_char_not_last_place":
            for element in password_list.copy():
                if find_regex("[^A-Za-z0-9]+", element[-1]):
                    password_list.remove(element)    
    return {"count": int(len(password_list))}

def decode_to_int(block):
    bytes = base64.b64decode(block)
    return int.from_bytes(bytes, byteorder='little')

def encode_from_int(integer):
    bytes = (integer).to_bytes(16, byteorder='little')
    return base64.b64encode(bytes).decode("utf-8") 

def handle_mul_gf2_128(assignment):
    block = assignment['block']
    alpha = decode_to_int('hwAAAAAAAAAAAAAAAAAAAAE=') # base64 encoded string for alpha function

    if decode_to_int(block) >= decode_to_int('AAAAAAAAAAAAAAAAAAAAgAA='): # base64 encoded equivalent for binary 1 followed by 127 times 0
        shifted = decode_to_int(block) << 1
        shifted = shifted ^ alpha
    else:
        shifted = decode_to_int(block) << 1
    times_alpha = encode_from_int(shifted)
    return {"block_times_alpha" : times_alpha}

def handle_block_cipher(assignment):
    key = assignment['key']
    if assignment['operation'] == 'encrypt':
        text = assignment['plaintext']
    else:
        text = assignment['ciphertext']
    if assignment['opmode'] == 'cbc':
        decoded_text = decode_to_int(text)
        decoded_iv = decode_to_int(assignment['iv'])

        text_xor_iv = decoded_text ^ decoded_iv

        # cbc
        return 0
    elif assignment['opmode'] == 'ctr':
        # ctr
        return 0
    else:
        # xex
        return 0

test_123= "VGhpcyBpcyB0aGUgcGxhaW50ZXh0IGV4YW1wbGUgdGhhdCB5b3Ugc2hvdWxkIGVuY3J5cHQgdXNpbmcgQ0JDIHdpdGhvdXQgcGFkZGluZy4="
str_1 = "Join our freelance network"

# convert string into bytes
str_1_bytes = str_1.encode()

# split bytes into array of bytes
str_1_bytes_array = bytearray(str_1_bytes)
# print(len(str_1_bytes_array))

# encode test_123 into bytes
test_123_bytes = base64.b64decode(test_123)

# split bytes into array of bytes
test_123_bytes_array = bytearray(test_123_bytes)
# print(len(test_123_bytes_array))

# split test_123_bytes_array by 16 bytes
test_123_bytes_array_16 = [test_123_bytes_array[i:i+16] for i in range(0, len(test_123_bytes_array), 16)]
# print(len(test_123_bytes_array_16))

# first element in test_123_bytes_array_16 is the iv
iv = test_123_bytes_array_16[0]
# print(iv)

# convert iv to int
iv_int = int.from_bytes(iv, byteorder='little')
# print(iv_int)

ihfau = "DlBD+b7U4Cw4usdbjG7tjA=="
ihfau_int = decode_to_int(ihfau)
# print(ihfau_int)

# xor iv and ihfau

xor_iv_ihfau = iv_int ^ ihfau_int
# print(xor_iv_ihfau)