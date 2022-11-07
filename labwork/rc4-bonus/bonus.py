def rc4_bonus2():
    key = []
    sbox = [i for i in range(256)]
    # print("Sbox pre:\n", sbox)
    
    sbox2 = [i for i in range(256)]
    sbox2[0] = 255
    sbox2[1] = 254
    sbox2[254] = 1
    sbox2[255] = 0

    # print(sbox2)
    j = j2 = 0
    for i in range(0, 3):
        j2 = (j2 + sbox[i]) % 256
        key.append((sbox2[i] - j2) % 256)
        j = (j + sbox[i] + key[i % len(key)]) % 256
        print(key[i])
        sbox[i], sbox[j] = sbox[j], sbox[i]
    # return sbox2, j
    print(sbox)

rc4_bonus2()