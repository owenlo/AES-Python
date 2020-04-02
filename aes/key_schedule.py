""" 
Based on Sam Trenholme's article and C code on Rijndael's key schedule
Source: https://www.samiam.org/key-schedule.html

Additional thanks to https://github.com/marprz for helping with translation.
"""

import constants

def rotate(inp):
  a = inp[0x00]
  for c in range(0x00, 0x03):
    inp[c] = inp[c + 0x01]
  inp[0x03] = a
  return inp


def rcon(inp):  
  c = 1
  if inp == 0:
    return 0
  while inp != 1:
    b = c & 0x80
    c = ( c << 1)
    if(b == 0x80):
      c = ( c^0x1b) % 0x100 #The mod is necessary to limit values to 255.
    inp = inp - 1  
  return c


def schedule(inp, i):
  rot = rotate(inp) #Rotate input 4 bytes left

  for r in range(0, 4):
    rot[r] = constants.sbox[rot[r]] #Perform s-box substitution on 4 bytes

  rot[0] ^= rcon(i) #Add 2^i on first byte  


def expand_key(inp, key_size=128):
    if(key_size == 128):
      expanded_size = 176
      c = 16
      offset = 16
    if(key_size == 192):
      expanded_size = 208
      c = 24
      offset = 24
    if(key_size == 256):
      expanded_size = 240
      c = 32
      offset = 32

    key = inp + ([None] * (expanded_size - len(inp)))
    t = [None] * 4        
    i = 1

    while c < expanded_size:
        for a in range (0, 4):
            t[a] = key[a + c - 4]
        if(c % offset == 0):
            schedule(t, i)
            i += 1
        if(key_size == 256):
            if (c % 32 == 16):
              for a in range(0, 4):
                t[a] = constants.sbox[t[a]]
        for a in range(0, 4):
            key[c] = key[c - offset] ^ t[a]
            c += 1           
    return key

def main():
  test_vector_128 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

  test_vector_192 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

  test_vector_256 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  
  key_expand_128 = expand_key(test_vector_128, 128)
  key_expand_192 = expand_key(test_vector_192, 192)
  key_expand_256 = expand_key(test_vector_256, 256)

  #Simple assertations to determine if the 128-bit, 192-bit and 256-bit test vectors were expanded correctly.
  if key_expand_128 == constants.key_expansion_result_128:
    print("PASS: 128-bit key expansion")
  else:
    print("FAIL: 128-bit key expansion")

  if key_expand_192 == constants.key_expansion_result_192:
    print("PASS: 192-bit key expansion")
  else:
    print("FAIL: 192-bit key expansion")

  if key_expand_256 == constants.key_expansion_result_256:
    print("PASS: 256-bit key expansion")
  else:
    print("FAIL: 256-bit key expansion")

  #The below code can be used to print out expanded key in a formatted output.
  """
  for index, res in enumerate(key_expand_128):
        print(hex(res),end=' ')
        if (index+1)%16 == 0:
            print('\n')
  """

if __name__ == "__main__":
  main()