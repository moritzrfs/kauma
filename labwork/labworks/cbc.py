from asyncio.windows_events import NULL
from labwork02 import * # import the labwork02 module
import requests
import json

# operation
operation = "encrypt"
key = "AAAAAAAAAAAAAAAAAAAAAA=="

# cbc encrypting
iv = "AAAAAAAAAAAAAAAAAAAAAA=="
plaintext = "VGhpcyBpcyB0aGUgcGxhaW50ZXh0IGV4YW1wbGUgdGhhdCB5b3Ugc2hvdWxkIGVuY3J5cHQgdXNpbmcgQ0JDIHdpdGhvdXQgcGFkZGluZy4="
ciphertext_result = ""

# convert plaintext into bytes of 16
plaintext_bytes = base64.standard_b64decode(plaintext)
plaintext_bytes_array = bytearray(plaintext_bytes)
print(plaintext_bytes_array)

# split plaintext_bytes_array by 16 bytes
plaintext_bytes_array_16 = [plaintext_bytes_array[i:i+16] for i in range(0, len(plaintext_bytes_array), 16)]
print(plaintext_bytes_array_16)

print("=========================================")

for p_b_a in plaintext_bytes_array_16:
    # print byte size of p_b_a
    print(len(p_b_a))
    # remove content from response
    response = NULL
    print("using plaintext:",p_b_a)
    # p_b_a to int
    p_b_a_int = int.from_bytes(p_b_a, byteorder='little')

    print("using plain int:",p_b_a_int)
    # decode iv to int
    iv_int = decode_to_int(iv)
    # print iv_int
    print("using iv: " + str(iv_int))
    # print iv
    print("using iv: " + str(iv))
    # xor p_b_a_int with iv_int
    p_b_a_int_xor_iv_int = p_b_a_int ^ iv_int

    print(p_b_a_int_xor_iv_int)
    # convert p_b_a_int_xor_iv_int to base64
    p_b_a_int_xor_iv_int_base64 = encode_from_int(p_b_a_int_xor_iv_int)

    # print p_b_a_int_xor_iv_int_base64
    print("using plaintext: " + str(p_b_a_int_xor_iv_int_base64))

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

    print("LENGTH CIPHER:", len(ciphertext))
    # set iv to ciphertext
    iv = ciphertext

    # remove == at the end from ciphertext
    ciphertext = ciphertext[:-2]  
    # add ciphertext to ciphertext_result
    ciphertext_result += ciphertext
    print("=====================================")

print(ciphertext_result)

s = "This is the plaintext example that you should encrypt using CBC without padding."