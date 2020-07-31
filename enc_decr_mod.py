# WEEK 4 Exersice

'''
Write a function that implements the following text ecryption scheme (normal text input and output). Remark that these aren't safe encryption schemes.:) 

We have a one-byte key and we encrypt all of the bytes of the plain text by adding the key for every byte and modulo by 256.

If you encrypt a text with a key then the decryption key will be 256-key (e.g. Encryption key 123, Decryption key: 133)

>>> encrypt_by_add_mod('Hello',123)
'Ãàççê'
>>> encrypt_by_add_mod(encrypt_by_add_mod('Hello',123),133)
'Hello'
>>> encrypt_by_add_mod(encrypt_by_add_mod('Cryptography',10),246)
'Cryptography'
'''

def encrypt_by_add_mod(string,k):
    h = string2hex(string)
    ret = ''
    for i in range(0,len(h),2):
        ret+=chr(((int(h[i:i+2],16))+k)%256)
    return ret
    
#OR

def encrypt_by_add_mod(string,k):
    hex_str = string2hex(string)
    list_int = [int(hex_str[i:i+2],16) for i in range(0,len(hex_str),2)]
    return ''.join(chr((j+k)%256) for j in list_int)
    

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
'''
We have a one byte sized key, xor the first byte of the plaintext and that will be the cipher for the first byte. 
To encrypt the second byte use the first byte of the message as key and so on. 


>>> encrypt_xor_with_changing_key_by_prev_cipher('Hello',123,'encrypt')
'3V:V9'
>>> encrypt_xor_with_changing_key_by_prev_cipher(encrypt_xor_with_changing_key_by_prev_cipher('Hello',123,'encrypt'),123,'decrypt')
'Hello'
>>> encrypt_xor_with_changing_key_by_prev_cipher(encrypt_xor_with_changing_key_by_prev_cipher('Cryptography',10,'encrypt'),10,'decrypt')
'Cryptography'
'''


def encrypt_xor_with_changing_key_by_prev_cipher(h,k,operation):
    if operation == 'encrypt':
        E= encrypt(h,k)
        return E
    elif operation == 'decrypt':
        D= decrypt(h,k)
        return D
    else:
        print('Wrong operation')        
        
def encrypt(h,k):
    h = string2hex(h)
    hh = [h[i:i+2] for i in range(0,len(h),2)]
    ret = []
    ret.append(hex_xor(hh[0],hex(k)[2:]))
    for i in hh[1:]:
        c = hex_xor(i,ret[-1])
        ret.append(c)
    return ''.join([chr(int(i,16)) for i in ret])

def decrypt(h,k):
    h = string2hex(h)
    hh = [h[i:i+2] for i in range(0,len(h),2)]
    ret = []
    ret.append(chr(int(hex_xor(hh[0],hex(k)[2:]),16)))
    for i in range(1,len(hh)):
        ret.append(chr(int(hex_xor(hh[i],hh[i-1]),16)))
    
    return ''.join(ret)
+----------------------------------------------------------------------+    
