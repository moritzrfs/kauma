import base64
import requests
import json
import sys
# import api_endpoint from main.py

api_endpoint = sys.argv[1]

session1 = requests.Session()
test_assignment =  {
        "ciphertext": "QBqQNIrwOnHATspnawRJUQ==",
        "iv": "w4EKfjyNLA9b5O3ay954nQ==",
        "keyname": "testkey-1",
        "private_data": {
          "key": "qzqdo96/Uqdq88DoRU0LRA=="
        }
}

def query_oracle_padding(_session : requests.Session, keyname: str, iv: str, ciphertext: str):
    payload = { "keyname": keyname, "iv": iv, "ciphertext": ciphertext }
    result = _session.post(api_endpoint + "/oracle/pkcs7_padding", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.text

def handle_pkcs7_padding(assignment):
    iv = base64.b64decode(assignment["iv"])
    iv = bytearray(iv)
    ciphertext = base64.b64decode(assignment["ciphertext"])
    test_iv = bytearray(16) # create empty test_iv to test against the oracle
    xor_result = bytearray(16) # create emptyy bytearray xor_result
    counter = 0
    for i in range(16, 0, -1): # loop through the 16 byte block starting from the last byte
        counter += 1            
        test_iv_pad = search_correct_padding(test_iv, ciphertext, assignment["keyname"], i-1)
        xor_result = prepare_iv(test_iv_pad, i-1, xor_result, counter)
    
    plain = decrypt_cbc(xor_result, iv)
    plain_b64 = base64.b64encode(plain).decode("utf8")
    print("plaintext: ", plain_b64)
    return {"plaintext": plain_b64 }
    
def search_correct_padding(test_iv, ciphertext, key, round):
    # set last_byte from 0 to ff
    for j in range(0, 256):
        # set last_byte to j
        test_iv[round] = j
        # print input_text_16b as hex
        # print(test_iv.hex())
        # input_text_16b base64 encode and decode utf8
        test_iv_16b_b64 = base64.b64encode(test_iv).decode("utf8")
        # ciphertext base64 encode and decode utf8
        ciphertext_b64 = base64.b64encode(ciphertext).decode("utf8")
        result = json.loads(query_oracle_padding(session1, key, test_iv_16b_b64, ciphertext_b64))['status']
        # print(result)
        # print("------------------")
        if result == 'padding_correct':
            # check special case first round
            if round == 15:
                # get first 15 bytes of test_iv
                inverted_test_iv = test_iv[0:round]
                # set all bytes to 0xff
                inverted_test_iv = bytearray([0xff] * len(inverted_test_iv))
                # add last byte of test_iv to inverted_test_iv
                inverted_test_iv += bytes([test_iv[round]])
                #base64 encode and decode utf8 inverted_test_iv
                inverted_test_iv_b64 = base64.b64encode(inverted_test_iv).decode("utf8")
                result_inv_test_iv = json.loads(query_oracle_padding(session1, key, inverted_test_iv_b64, ciphertext_b64))['status']
                if result_inv_test_iv == 'padding_correct':
                    return test_iv
            else:
                print(test_iv.hex())            
                return test_iv
    
def prepare_iv(test_iv: bytearray, round: int, xor_result: bytearray, counter: int) -> bytearray:
    xor_result[round] = test_iv[round] ^ counter
    print("prepare_iv:", xor_result)
    print(xor_result.hex())
    for i in range (0, counter):
        test_iv[15-i] = xor_result[15-i] ^ counter+1
    print("test_iv:", test_iv)
    print(test_iv.hex())
    return xor_result

def decrypt_cbc(xor_result: bytearray, iv: bytearray):
    plaintext = b''
    for i in range(0, 16):
        plaintext += bytes([xor_result[i] ^ iv[i]])    
    last_byte = plaintext[-1] # get last byte of plaintext

    if plaintext[-last_byte:] == bytes([last_byte] * last_byte): # check if last x bytes of plaintext are equal to last_byte
         plaintext = plaintext[:-last_byte] # remove last x bytes from plaintext

    return plaintext

handle_pkcs7_padding(test_assignment)