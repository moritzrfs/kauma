import base64
import json
import sys
import requests

api_endpoint = sys.argv[1]

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

def handle_gcm_block_to_poly(assignment):
    block = base64.b64decode(assignment['block'])
    block_int = int.from_bytes(block, byteorder='big')
    poly = []
    for i in range(128):
        if block_int & (1 << i):
            poly.append(128-i-1)
    poly.sort()
    return { "coefficients": poly}

def handle_gcm_mul_gf2_128(assignment):
    poly_a = handle_gcm_block_to_poly({ 'block' : assignment['a'] })
    poly_b = handle_gcm_block_to_poly({ 'block' : assignment['b'] })

    # handle case where  either a or b or both  are 0 at this positions
    # since no polynoms are returned to be handled by the multiplication followed
    if len(poly_b['coefficients']) == 0: 
        return { "a*b": assignment['a'] }
    elif len(poly_a['coefficients']) == 0: # handle case where a is 0
        return { "a*b": assignment['b'] }

    polys = []
    for i in range(len(poly_a['coefficients'])):
        for j in range(len(poly_b['coefficients'])):
            to_add = poly_a['coefficients'][i] + poly_b['coefficients'][j]
            poly_append(polys, to_add)
    polys.sort(reverse=True)

    while polys[0] > 127:
        highest = polys[0]        
        polys.remove(polys[0])
        poly_append(polys, highest - 128)
        poly_append(polys, highest - 127)
        poly_append(polys, highest - 126)
        poly_append(polys, highest - 121)
        polys.sort(reverse=True)# sort descending    
    result = 0

    for i in range(len(polys)):
        result += 2 ** polys[i]
    result_bytes = bytearray(result.to_bytes(16, byteorder='little'))

    for i in range(16):
        result_bytes[i] = reverse_Bits(result_bytes[i])
    result_b64 = base64.b64encode(result_bytes).decode('utf-8')

    return { "a*b": result_b64 }

def query_oracle(session: requests.Session, keyname: str, ciphertext: str) -> str:
    payload = { "keyname": keyname, "ciphertext": ciphertext }
    result = session.post(api_endpoint + "/oracle/cbc_key_equals_iv", headers = {
        "Content-Type": "application/json"}, data = json.dumps(payload))
    assert(result.status_code == 200)
    return result.json()['plaintext']

def poly_append(polys: list, to_add: int):
    if to_add in polys:
        polys.remove(to_add)
    else:
        polys.append(to_add)
    polys.sort(reverse=True)

def reverse_Bits(block: int) -> int:
    result = 0
    for i in range(8):
        result <<= 1
        result |= block & 1
        block >>= 1
    return result