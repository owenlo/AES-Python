""" 
AES encryption and decryption using Electronic Codebook (ECB) method
"""

import key_schedule, constants

def encrypt(plaintext, key, size=128):    
    aes_round = 0

    key = key_schedule.expand_key(key, 128)

    if (size ==128):
        aes_total_rounds = 10

    key_offset = 16
    cipher = addRoundKey(plaintext, key[0:key_offset])

    while aes_round < aes_total_rounds:
        cipher = subBytes(cipher)    
        cipher = shiftRows(cipher) 

        if(aes_round < (aes_total_rounds - 1)): #Mix column is not done during final round
            col1 = mixColumns([ cipher[0], cipher[1], cipher[2], cipher[3]])
            col2 = mixColumns([ cipher[4], cipher[5], cipher[6], cipher[7]])
            col3 = mixColumns([ cipher[8], cipher[9], cipher[10], cipher[11]])
            col4 = mixColumns([ cipher[12], cipher[13], cipher[14], cipher[15]])
            cipher = col1 + col2 + col3 + col4

        aes_round += 1
        key_offset += 16
        cipher = addRoundKey(cipher, key[key_offset - 16:key_offset])   
       
    return cipher

def addRoundKey(inp, key):  
    for i in range(0, 16):
        inp[i] = inp[i]^key[i]
    return inp

def subBytes(inp):
    sbox_lookup = [None] * 16
    for i in range(0, 16):
        sbox_lookup[i] = constants.sbox[inp[i]]

    return sbox_lookup

def shiftRows(inp):  
    inp[1], inp[5], inp[9], inp[13] = inp[5], inp[9], inp[13], inp[1]
    inp[2], inp[6], inp[10], inp[14] = inp[10], inp[14], inp[2], inp[6] 
    inp[3], inp[7], inp[11], inp[15] = inp[15], inp[3], inp[7], inp[11] 

    return inp

"""
Based on Sam Trenholme's article and C code on AES mix column
https://www.samiam.org/mix-column.html
"""
def mixColumns(inp):
    a = [None] * 4
    b = [None] * 4

    for c in range(0, 4):
        a[c] = inp[c]
        h = inp[c] & 0x80
        b[c] = (inp[c] << 1)

        if(h == 0x80):
            b[c] = (b[c] ^ 0x1b) % 0x100

    inp[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
    inp[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
    inp[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
    inp[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]

    return inp

def main():

    plaintext_128 = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]
    key_128 =       [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

    cipher_128 = encrypt(plaintext_128, key_128, 128)

    if(cipher_128 == constants.encryption_result_128_ECB):
        print("PASS: 128-bit Encryption")
    else:
        print("FAIL: 128-bit Encryption")

if __name__ == "__main__":
    main()
     