import base64
import itertools
import json
import re
import sys
import requests

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

def handle_cbc(assignment):
    text_result = b''
    session = requests.Session()
    iv_16b = base64.b64decode(assignment['iv']) # base64 decode iv 
    if assignment['operation'] == 'encrypt': 
        for i in range(0, len(base64.b64decode(assignment['plaintext'])), 16):
            plaintext_16b = base64.b64decode(assignment['plaintext'])[i:i+16]                    
            xor_result = handle_xor(plaintext_16b, iv_16b) # xor plaintext_byte with iv_bytes
            xor_result = base64.b64encode(xor_result).decode('utf-8') # base64 encode xor_result
            ciphertext = json.loads(query_oracle(session, xor_result, assignment['operation'], assignment['key']))["ciphertext"]
            iv_16b = base64.b64decode(ciphertext)
            text_result += base64.b64decode(ciphertext)
        return {"ciphertext": base64.b64encode(text_result).decode('utf-8')}
    elif assignment['operation'] == 'decrypt':
        plaintext_oracle = json.loads(query_oracle(session, assignment['ciphertext'], assignment['operation'], assignment['key']))["plaintext"]
        for i in range(0, len(base64.b64decode(plaintext_oracle)), 16):
            ciphertext_16b = base64.b64decode(plaintext_oracle)[i:i+16]    
            cipher_pre = base64.b64decode(assignment['ciphertext'])[i:i+16]
            xor_result = handle_xor(ciphertext_16b, iv_16b)
            xor_result = base64.b64encode(xor_result).decode('utf-8')                
            iv_16b = cipher_pre
            text_result += base64.b64decode(xor_result)
        return {"plaintext" : base64.b64encode(text_result).decode('utf-8')}

def handle_ctr(assignment):
    session = requests.Session()
    text_result = b''
    input_text = assignment['plaintext'] if assignment['operation'] == 'encrypt' else assignment['ciphertext']
    for i in range(0, len(base64.b64decode(input_text)), 16):
        input_text_16b = base64.b64decode(input_text)[i:i+16]
        nonce = base64.b64decode(assignment['nonce']) + int(i/16).to_bytes(4, byteorder='big')
        nonce = base64.b64encode(nonce).decode('utf-8')
        enc_nonce = json.loads(query_oracle(session, nonce, "encrypt", assignment['key']))["ciphertext"]
        xor_result = handle_xor(input_text_16b, base64.b64decode(enc_nonce))
        text_result += xor_result
    return {"ciphertext" if assignment['operation'] == 'encrypt' else "plaintext" : base64.b64encode(text_result).decode('utf-8')}

def handle_xex(assignment):
    session = requests.Session()
    text_result = b''
    input_text = assignment['plaintext'] if assignment['operation'] == 'encrypt' else assignment['ciphertext']
    key = base64.b64decode(assignment['key'])
    key1 = key[:16]
    key2 = key[16:]
    enc_tweak = json.loads(query_oracle(session, assignment['tweak'], "encrypt", base64.b64encode(key2).decode('utf-8')))["ciphertext"]   
    for i in range(0, len(base64.b64decode(input_text)), 16):
        input_text_16b = base64.b64decode(input_text)[i:i+16]        
        xor_result = handle_xor(input_text_16b, base64.b64decode(enc_tweak))
        enc_text = json.loads(query_oracle(session, base64.b64encode(xor_result).decode('utf-8'), assignment['operation'], base64.b64encode(key1).decode('utf-8')))["ciphertext" if assignment['operation'] == 'encrypt' else "plaintext"]
        xor_result = handle_xor(base64.b64decode(enc_text), base64.b64decode(enc_tweak))
        text_result += xor_result
        mul_128_assignment = {"block": enc_tweak}
        enc_tweak = handle_mul_gf2_128(mul_128_assignment)["block_times_alpha"]
    return {"ciphertext" if assignment['operation'] == 'encrypt' else "plaintext" : base64.b64encode(text_result).decode('utf-8')}
        
def handle_block_cipher(assignment):
    if assignment['opmode'] == 'cbc':
        return handle_cbc(assignment)            
    elif assignment['opmode'] == 'ctr':
        return handle_ctr(assignment)        
    elif assignment['opmode'] == 'xex':
        return handle_xex(assignment)

def handle_xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

def query_oracle(session, text, operation, key):
    # put request to server
    if operation == 'encrypt':
        payload = {"operation" : operation, "key" : key, "plaintext" : text}
    elif operation == 'decrypt':
        payload = {"operation" : operation, "key" : key, "ciphertext" : text}
    result = session.post(sys.argv[1]+"/oracle/block_cipher", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.text