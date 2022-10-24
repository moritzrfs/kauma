import base64
import json
import sys
import requests

api_endpoint = sys.argv[1]

def query_oracle(session: requests.Session, keyname: str, ciphertext: str) -> str:
    payload = { "keyname": keyname, "ciphertext": ciphertext }
    result = session.post(api_endpoint + "/oracle/cbc_key_equals_iv", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.json()['plaintext']

def handle_cbc_key_equals_iv(assignment):
    session = requests.session()
    ciphertext = base64.b64decode(assignment['valid_ciphertext'])
    total_length = len(ciphertext)
    last_block = ciphertext[total_length-16:total_length]
    second_last_block = ciphertext[total_length-32:total_length-16]
    block_modified = ciphertext[0:16] + bytes([0] * 16) + ciphertext[0:16] + second_last_block + last_block
    ciphertext_modified = base64.b64encode(block_modified).decode('utf-8')
    plaintext_modified_b64 = base64.b64decode(query_oracle(session, assignment['keyname'], ciphertext_modified))
    key = base64.b64encode(bytes([a ^ b for a, b in zip(plaintext_modified_b64[0:16], plaintext_modified_b64[32:48])])).decode('utf-8')
    return { "key": key }