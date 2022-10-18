import base64
import requests
import json
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
    result = _session.post("https://dhbw.johannes-bauer.com/lwsub/oracle/pkcs7_padding", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.text

def handle_pkcs7_padding(assignment):
    iv = assignment["iv"]
    ciphertext = base64.b64decode(assignment["ciphertext"])

    # get bytesize of the ciphertext
    bytesize = len(ciphertext)
    print("bytesize: ", bytesize)

    # create empty block of 16 bytes
    test_iv = bytearray(16)

    # create bytearray xor_result
    xor_result = bytearray(16)
    # loop 16 times
    counter = 0
    for i in range(16, 0, -1):
        counter += 1            
        test_iv_pad = search_correct_padding(test_iv, ciphertext, assignment["keyname"], i-1)
        prepare_iv(test_iv_pad, i-1, xor_result, counter)
       
def search_correct_padding(test_iv, ciphertext, key, round):
    # set last_byte from 0 to ff
    for j in range(0, 256):
        # set last_byte to j
        test_iv[round] = j
        # print input_text_16b as hex
        print(test_iv.hex())
        # input_text_16b base64 encode and decode utf8
        test_iv_16b_b64 = base64.b64encode(test_iv).decode("utf8")
        # ciphertext base64 encode and decode utf8
        ciphertext_b64 = base64.b64encode(ciphertext).decode("utf8")
        result = json.loads(query_oracle_padding(session1, key, test_iv_16b_b64, ciphertext_b64))['status']
        print(result)
        print("------------------")
        if result == 'padding_correct':
            print(test_iv)
            return test_iv
    
def prepare_iv(test_iv: bytearray, round: int, xor_result: bytearray, counter: int):
    xor_result[round] = test_iv[round] ^ counter
    print("prepare_iv:", xor_result)


handle_pkcs7_padding(test_assignment)

# barraytest = bytearray(16)
# barraytest[5] = 1
# element = bytes(barraytest)
# print(element)

# barraytest[1]