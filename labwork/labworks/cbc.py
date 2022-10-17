import base64
import requests
import json

def decode_to_int(block):
    bytes = base64.b64decode(block)
    return int.from_bytes(bytes, byteorder='little')

def encode_from_int(integer):
    bytes = (integer).to_bytes(16, byteorder='little')
    return base64.b64encode(bytes).decode("utf-8") 

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

# operation
operation = "encrypt"
key = "AAAAAAAAAAAAAAAAAAAAAA=="
# cbc encrypting
iv = "AAAAAAAAAAAAAAAAAAAAAA=="
plaintext = "VGhpcyBpcyB0aGUgcGxhaW50ZXh0IGV4YW1wbGUgdGhhdCB5b3Ugc2hvdWxkIGVuY3J5cHQgdXNpbmcgQ0JDIHdpdGhvdXQgcGFkZGluZy4="
ciphertext_result = b''

# convert plaintext into bytes of 16
plaintext_bytes = base64.b64decode(plaintext)
for i in range(0, len(plaintext_bytes), 16):
    plaintext_byte = plaintext_bytes[i:i+16]    
    # base64 decode iv
    iv_bytes = base64.b64decode(iv)
    # xor plaintext_byte with iv_bytes
    xor_result = xor(plaintext_byte, iv_bytes)
    # base64 encode xor_result
    xor_result = base64.b64encode(xor_result).decode('utf-8')
    print(xor_result)
    # put request to server
    url = "https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher"
    payload = {
        "operation" : operation,
        "key" : key,
        "plaintext" : xor_result,
    }
    headers = {
		"Content-Type": "application/json",
	}
    response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
    print(response.text)

    # get ciphertext from response
    ciphertext = json.loads(response.text)["ciphertext"]


    iv = ciphertext

    ciphertext_result += base64.b64decode(ciphertext)

print(base64.b64encode(ciphertext_result).decode('utf-8'))
    
plaintext_bytes_array = bytearray(plaintext_bytes)
print(plaintext_bytes_array)

# split plaintext_bytes_array by 16 bytes
plaintext_bytes_array_16 = [plaintext_bytes_array[i:i+16] for i in range(0, len(plaintext_bytes_array), 16)]
print(plaintext_bytes_array_16)

'''print("=========================================")
for p_b_a in plaintext_bytes_array_16:
    # p_b_a to int
    p_b_a_int = int.from_bytes(p_b_a, byteorder='little')
    # decode iv to int
    iv_int = decode_to_int(iv)
    # xor p_b_a_int with iv_int
    p_b_a_int_xor_iv_int = p_b_a_int ^ iv_int
    # convert p_b_a_int_xor_iv_int to base64
    p_b_a_int_xor_iv_int_base64 = encode_from_int(p_b_a_int_xor_iv_int)
    # put request to server
    url = "https://dhbw.johannes-bauer.com/lwsub/oracle/block_cipher"
    payload = {
        "operation" : operation,
        "key" : key,
        "plaintext" : p_b_a_int_xor_iv_int_base64,
    }
    headers = {
		"Content-Type": "application/json",
	}
    response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
    print(response.text)
    # get ciphertext from json response
    ciphertext = json.loads(response.text)["ciphertext"]

    print(ciphertext)
    # set iv to ciphertext
    iv = ciphertext
    # remove == at the end from ciphertext
    ciphertext = ciphertext[:-2]  
    # add ciphertext to ciphertext_result
    ciphertext_result += ciphertext
    print("=====================================")

print(ciphertext_result)'''