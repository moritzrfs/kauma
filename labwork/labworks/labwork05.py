import base64
import json
import sys
import requests

api_endpoint = sys.argv[1]
session = requests.Session()

def iv_string_handle(iv_dump) -> bytearray:
    iv_dump = base64.b64decode(iv_dump)
    iv_dumps = [iv_dump[i:i+4] for i in range(0, len(iv_dump), 4)]
    return iv_dumps

def handle_ksa(key: bytes, key_length: int):
    s = [i for i in range(256)]
    j = 0
    for i in range(0, key_length):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s, j

def handle_rc4_fms(assignment, tcid):
    iv_dump = assignment['captured_ivs']
    key_length = assignment['key_length']
    ivs = iv_string_handle(iv_dump)
    key = bytearray(key_length)
    search_arr = [0,0]
    round = 0
    test_result = False
    while not test_result:        
        for i in range(key_length):
            filtered_ivs = filter_ivs(ivs, i, key)
            item = get_occurence(filtered_ivs, search_arr, i)
            most_common_b = item.to_bytes(1, byteorder='big')
            key[i] = most_common_b[0]
        test_result = handle_test_result(key, tcid)
        round += 1
        search_arr = occurence_tree(search_arr, round)
        # print("Key:", key)
    key = base64.b64encode(key).decode('utf-8')
    print("Key as base64:", key)
    return {"key" : key}

def filter_ivs(ivs: list[bytes], byte_index: int, key: bytearray) -> list:
    results = []
    # convert ivs to bytearray
    ivs = [bytearray(iv) for iv in ivs]
    for i in range(len(ivs)):
        if ivs[i][0] == byte_index + 3 and ivs[i][1] == 255:
            # ksa mit 3 schritten auf iv
            if  byte_index == 0:
                iv_with_key = ivs[i][0:3]
            else:
                iv_with_key = bytearray(ivs[i][0:3] + key[0:byte_index])
            sbox, j = handle_ksa(iv_with_key, byte_index + 3)
            inverted_sbox = invert_sbox(sbox)
            result_key = (inverted_sbox[ivs[i][3]] - j - sbox[byte_index + 3]) % 256
            results.append(result_key)
    return results

def get_occurence(results: list, search_arr: list, i: int) -> dict:
    occurences = {}
    for item in results:
        if (item in occurences):
            occurences[item] += 1
        else:
            occurences[item] = 1
    if search_arr[0] == i:
        result = sorted(occurences.items(), key=lambda x: x[1], reverse=True)[search_arr[1]][0]
    else:
        result = sorted(occurences.items(), key=lambda x: x[1], reverse=True)[0][0]    
    return result

def invert_sbox(sbox: list[int]) -> list[int]:
    inverse = [0] * len(sbox)
    for i in range(len(sbox)):
        inverse[sbox[i]] = i
    return inverse

def handle_test_result(key, tcid):
    key = base64.b64encode(key).decode('utf-8')
    result = session.post(api_endpoint + "/submission/" + tcid, headers = {
		"Content-Type": "application/json",
	}, data = json.dumps({"key" : key}))
    if result.json()["status"] == "pass":
        return True
    else:
        return False

def occurence_tree(arr, round):
    if (round -1) % 16 == 0:
        arr[1] += 1
        arr[0] = 0
    else:
        arr[0] += 1
    # print("Occurence tree:", arr, "Round:", round)
    return arr

def bonus():
    ksa = []
    sbox = [i for i in range(256)]

    pseudoj = 0
    for i in range(256):
        new = 256 - pseudoj 
        ksa.append(new)
        pseudoj = (pseudoj + sbox[i] + ksa[i]) % 256
        
    j = 0
    for i in range(256):
        print("j: ",j)
        print("sbox[i]: ",sbox[i])
        print("ksa[i]: ",ksa[i])
        j = (j + sbox[i] + ksa[i]) % 256
        print("Ergebnis: ",j,i)
        print()
        sbox[i], sbox[j] = sbox[j], sbox[i]
    print(ksa)
    print(sbox)

bonus()