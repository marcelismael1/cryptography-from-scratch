'''
AES
Create a function that encrypts a message with AES CBC mode with the given IV and key. Here you must use an external AES library that implements the encprytion scheme.

https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html (Links to an external site.)

>>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
>>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
>>> decrypt_aes(bytes([255, 18, 67, 115, 172, 117, 242, 233, 246, 69, 81, 156, 52, 154, 123, 171]),key,iv)
b'hello world 1234'
>>> decrypt_aes(bytes([171, 218, 160, 96, 193, 134, 73, 81, 221, 149, 19, 180, 31, 247, 106, 64]),key,iv)
b'lovecryptography'
'''

from Crypto.Cipher import AES

def decrypt_aes(ciphertext,key,iv):

    cipher = AES.new(key, AES.MODE_CBC,iv) # Block mode cipher
    
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext
    

key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
decrypt_aes(bytes([255, 18, 67, 115, 172, 117, 242, 233, 246, 69, 81, 156, 52, 154, 123, 171]),key,iv)


def bit_permutation(string,order):
    newstring = ''.join([string[pos-1] for pos in order])
    return newstring
    

def left_shift_rot(binary, rot=1):
    while rot>0:
        binary = binary[1:]+binary[0]
        rot-=1   
    return binary
    
    
def PKCS7_pad(string,padding):
    res = list(string)
    padding = padding - len(string)
    res = ''.join(string) + chr(padding)*padding    
    return res