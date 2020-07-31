# Marcel Ismael
# 06- Apr -2020

from Crypto.Cipher import AES

key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])


# decrypt_aes_ecb
# Last week we used the AES library in CBC mode. Now create a function that uses the same library and decrypt a message that is coded in ECB mode.

def decrypt_aes_ecb(ciphertext,key):

    cipher = AES.new(key, AES.MODE_ECB) # Block mode cipher
    
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext


# xor_byte_arrays
# Create a function that xors two byte array.  Not that you can use rjust on byte strings arrays as well, like input1_padded = input1.rjust(max_len,bytes([0]))

def xor_byte_arrays(a,b):
    max_len = max(len(a),len(b))
    a = a.rjust(max_len,bytes([0]))
    b = b.rjust(max_len,bytes([0]))
    r = list(zip(a,b))
    res = [x^y for x,y in r]
    return bytes(res)


# decrypt_aes_cbc_with_ecb
# Implement AES in CBC mode with the previous function
# Every encryption CBC encryption method can be built from the implementation of the ECB mode.

def decrypt_aes(ciphertext,key,iv):
    cipher = AES.new(key, AES.MODE_CBC,iv) # Block mode cipher
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def decrypt_aes_cbc_with_ecb(cipher, key,iv):
    dec_ebc = decrypt_aes_ecb(cipher,key)
    return xor_byte_arrays(dec_ebc,iv)



# encrypt_aes_cbc_with_ecb
# Create a function that implements the AES encryption in CBC mode, using only AES in ECB mode.

def encrypt_aes_cbc_with_ecb(plaintext, key ,iv):
    p = xor_byte_arrays(plaintext,iv)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(p)
    return ciphertext
 
 
decrypt_aes(encrypt_aes_cbc_with_ecb(bytes(b'hello world 1234'),key,iv),key,iv)




