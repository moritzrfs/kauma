import base64
import binascii
import itertools
import json
import re
import sys
from tokenize import String

import requests

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
    print(assignment['opmode'])
    if assignment['opmode'] == 'cbc':
        text_result = b''
        session = requests.Session()
        if assignment['operation'] == 'encrypt':
            print("Handling encyption")
            print("Using key: " + assignment['key'])
            iv_16b = base64.b64decode(assignment['iv']) # base64 decode iv  
            for i in range(0, len(base64.b64decode(assignment['plaintext'])), 16):
                plaintext_16b = base64.b64decode(assignment['plaintext'])[i:i+16]                    
                xor_result = handle_xor(plaintext_16b, iv_16b) # xor plaintext_byte with iv_bytes
                xor_result = base64.b64encode(xor_result).decode('utf-8') # base64 encode xor_result
                ciphertext = json.loads(query_oracle(session, xor_result, assignment['operation'], assignment['key']))["ciphertext"]
                iv_16b = base64.b64decode(ciphertext)
                text_result += base64.b64decode(ciphertext)
            print({"ciphertext": base64.b64encode(text_result).decode('utf-8')})
            return {"ciphertext": base64.b64encode(text_result).decode('utf-8')}
        elif assignment['operation'] == 'decrypt':
            print("Handling decryption")
            print("Using key: " + assignment['key'])
            plaintext_oracle = json.loads(query_oracle(session, assignment['ciphertext'], assignment['operation'], assignment['key']))["plaintext"]
            iv_16b = base64.b64decode(assignment['iv']) # base64 decode iv  
            for i in range(0, len(base64.b64decode(plaintext_oracle)), 16):
                ciphertext_16b = base64.b64decode(plaintext_oracle)[i:i+16]    
                cipher_pre = base64.b64decode(assignment['ciphertext'])[i:i+16]
                xor_result = handle_xor(ciphertext_16b, iv_16b)
                xor_result = base64.b64encode(xor_result).decode('utf-8')                
                iv_16b = cipher_pre
                text_result += base64.b64decode(xor_result)
            print({"ciphertext": base64.b64encode(text_result).decode('utf-8')})
            return {"plaintext" : base64.b64encode(text_result).decode('utf-8')}
            
    elif assignment['opmode'] == 'ctr':
        # ctr
        return 0
    else:
        # xex
        return 0

def handle_xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

def handle_cbc(assignment):
    print("Handling Testcase with iv: ", assignment['iv'])
    print("Handling Testcase with operation: ", assignment['operation'])    

def query_oracle(session, text, operation, key):
    # put request to server
    if operation == 'encrypt':
        payload = {"operation" : operation, "key" : key, "plaintext" : text}
    elif operation == 'decrypt':
        payload = {"operation" : operation, "key" : key, "ciphertext" : text}
    result = session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.text