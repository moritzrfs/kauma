import base64
import requests
import json
import sys

api_endpoint = sys.argv[1]

test_assignment = {
                "ciphertext": "nJTw6DxUrZWy/BKSEWKF5xqO6KzoV67wdLLRtGh/yYc=",
                "iv": "N0t8zbx/e0ji6qPFrxGHjA==",
                "keyname": "prodkey"
            }

def query_oracle_padding(_session : requests.Session, keyname: str, iv: str, ciphertext: str):
    payload = { "keyname": keyname, "iv": iv, "ciphertext": ciphertext }
    result = _session.post(api_endpoint + "/oracle/pkcs7_padding", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.text

def handle_pkcs7_padding(assignment):
    session1 = requests.Session()
    multiple_xor_result = bytearray()
    plaintext = bytearray()
    ciphertext_b64 = base64.b64decode(assignment['ciphertext'])
    for i in range(0, len(ciphertext_b64), 16):
        ciphertext_b64_block = ciphertext_b64[i:i+16]
        iv = base64.b64decode(assignment["iv"])
        iv = bytearray(iv)
        test_iv = bytearray(16) # create empty test_iv to test against the oracle
        xor_result = bytearray(16) # create emptyy bytearray xor_result
        counter = 0
        for i in range(16, 0, -1): # loop through the 16 byte block starting from the last byte
            counter += 1            
            test_iv_pad = search_correct_padding(test_iv, ciphertext_b64_block, assignment["keyname"], i-1, session1) # search for correct padding
            xor_result = prepare_iv(test_iv_pad, i-1, xor_result, counter)
        multiple_xor_result += xor_result

    for i in range(0, len(multiple_xor_result), 16):
        plaintext += decrypt_cbc(multiple_xor_result[i:i+16], iv)
        iv = ciphertext_b64[i:i+16] # set iv to the last block of ciphertext
    unpadded = remove_padding(plaintext)
    unpadded_plaintext_b64 = base64.b64encode(unpadded).decode("utf8")
    return {"plaintext": unpadded_plaintext_b64 }
    
def search_correct_padding(test_iv, ciphertext, key, round, session):
    for j in range(0, 256): # set last_byte from 0 to ff
        test_iv[round] = j
        test_iv_16b_b64 = base64.b64encode(test_iv).decode("utf8")
        ciphertext_b64 = base64.b64encode(ciphertext).decode("utf8")
        result = json.loads(query_oracle_padding(session, key, test_iv_16b_b64, ciphertext_b64))['status']
        if result == 'padding_correct':
            if round == 15:# check false positive first round                
                inverted_test_iv = bytearray([0xff] * 15) # set all bytes to 0xff                
                inverted_test_iv += bytes([test_iv[round]]) # add last byte of test_iv to inverted_test_iv
                inverted_test_iv_b64 = base64.b64encode(inverted_test_iv).decode("utf8")
                result_inv_test_iv = json.loads(query_oracle_padding(session, key, inverted_test_iv_b64, ciphertext_b64))['status']
                if result_inv_test_iv == 'padding_correct':
                    return test_iv
                else:
                    continue
            else:
                return test_iv
    
def prepare_iv(test_iv: bytearray, round: int, xor_result: bytearray, counter: int) -> bytearray:
    xor_result[round] = test_iv[round] ^ counter
    for i in range (0, counter):
        test_iv[15-i] = xor_result[15-i] ^ counter+1
    return xor_result

def decrypt_cbc(xor_result: bytearray, iv: bytearray):
    plaintext = b''
    for i in range(0, 16):
        plaintext += bytes([xor_result[i] ^ iv[i]])
    return plaintext

def remove_padding(plaintext: bytes):
    plaintext = bytearray(plaintext)
    last_byte = plaintext[-1]
    if plaintext[-last_byte:] == bytes([last_byte] * last_byte): # check if last x bytes of plaintext are equal to last_byte
        plaintext = plaintext[:-last_byte]
    return plaintext