def rc4_bonus():
    key = []
    sbox = [i for i in range(256)]
    print("Sbox pre:\n", sbox)
    j = 0
    for i in range(256): # key [256, 256, 255, 254, ... 2]
        key.append(256 - j)
        j = (j + sbox[i] + key[i]) % 256
    j = 0
    for i in range(256): # test against sbox
        j = (j + sbox[i] + key[i]) % 256
        print("j, i: ",j,i)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    print("Sbox post:\n", sbox)
    print("Used key:\n", key)