# Marcel Ismael

# Below are all the needed functions to perform DES encryption algorithm
# at the end there is a test funcion to test the algorithm by comparing 
# the results with Cryptodome DES code


# Common Functions
def bytes2binary(b):
    bb=int.from_bytes(b, byteorder='big')
    bb = bin(bb)[2:]
    target_length = len(bb) + (8 - len(bb) % 8) % 8
    
    # Solve and exception
    j = 0
    while b[j]==0:
        target_length =target_length+8
        j+=1
    return bb.zfill(target_length)

def binary2bytes(b):
    #Pad the input bytes
    target_length = len(b) + (8 - len(b) % 8) % 8
    b= b.zfill(target_length)
    
    # Creat a array of integers of the input binary
    b_arr = [int(b[i:i+8],2) for i in range(0,len(b),8)]
    # return the bytes of the integer array
    return bytes(b_arr)
 
def bin_xor(b1,b2):
    #perform xor between integers
    b = int(b1,2)^int(b2,2)
    #get max len
    max_len = max(len(b1),len(b2))
    #return binary value of xor result and padded with the max len
    return bin(b)[2:].zfill(max_len)
    

############################## DES #######################

# Common lists
key_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63,55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
# tables for encryption

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]
IP_inverse = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]


# Tables for function f

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

S = \
[
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25]
#+++++++++++++++create_DES_subkeys +++++++++++++++++++++#

# Supporting Functions

# to premutate main list based on an indexed list
def premutate(main_list,index_list):
    '''
    to premutate main list based on an indexed list
    '''
    index_l = [main_list[i-1] for i in index_list]
    return index_l


# Shift Function
def shift_fun(a,s=1):
    '''
    input an bit string and shift one bit 
    to the left s times.
    a : bit string
    s : integer (number of shifts)
    '''
    while s!=0:
        a = a[1:]+a[0]
        s-=1
    return a

# Main Functon
def create_DES_subkeys (key_value):
    '''
    Create the list of Kn subkeys
    key_value :  is a 64 bit key
    
    EXAMPLE:
    create_DES_subkeys('0001001100110100010101110111100110011011101111001101111111110001')
    '''
    # Generate permuted key K+
    kk = premutate(key_value,PC1)
    
    # Create CD array
    c0 = ''.join(kk[:28])
    d0 = ''.join(kk[28:])
    
    # List of tuples of (Cn,Dn)
    # Based on key_shifts
    CD = [(c0,d0)]
    for i in range(len(key_shifts)):
        c = shift_fun(CD[i][0],key_shifts[i])
        d = shift_fun(CD[i][1],key_shifts[i])
        CD.append((c,d))
        
    # Create final keys array
    keys= [''.join(premutate(CD[i][0]+CD[i][1],PC2)) for i in range(1,17)]
    
    return keys


#======================================================================#

#+++++++++++++++++++++ Encryption +++++++++++++++++++++++++++++++#
#  Create E function that expand 32bit to 48bit long
def expand(k,sel_table=E):
    '''
    This will expand a 32bit bit string to 48bit string
    according to index table called E (selection table)
    EXAMPLE:
    expand('11110000101010101111000010101010',E)
    '''
    res = [k[i-1] for i in sel_table]
    return ''.join(res)


# Calculate the S finction Si(Bi) B is 6bit binaryblock
def shrink(b,s_table):
    '''
    This func shrinks a 6 bit block to 4bit block
    b : 6bit bit clock
    s_table : a selection table
        
    S('011011') = '0101'
    '''
    row = int(b[0]+b[-1],2)
    col = int(b[1:-1],2)
    
    return bin(s_table[row][col])[2:].zfill(4)
 
 
# Create the f(Rn-1, Kn)
def f(lr,k):
    '''
    lr : 32bit bit string block message
    Kn : 48bit bit string key
    '''
    # Expand L or R 32bit to 48bit
    exp_lr = expand(lr,E)
    
    # XOR with 48bit key
    res = bin_xor(exp_lr,k)
    result = ''
    s_table_num = 0
    
    # produce the 8x4bit blocks 
    for i in range(0,len(res),6):
        s= shrink(res[i:i+6],S[s_table_num])
        result+=s
        s_table_num += 1
    
    # Premutation the result of S table shrink with P table
    # 32bit result
    return ''.join(premutate(result,P)) 

def encrypt_DES(key,message):
    '''
    encrypt wit DES algorithm
    message = is byte message
    key = 64 bit key
    
    EXAMPLE:
    Key = b'\x13\x34\x57\x79\x9b\xbc\xdf\xf1'
    Message = b'\x01\x23\x45\x67\x89\xab\xcd\xef'
    encrypt_DES(Key,Message)
    b'\x85\xe8\x13T\x0f\n\xb4\x05'

    '''
    # Get binary values
    key = bytes2binary(key)
    #print('Byte_message  :',message)
    message = bytes2binary(message)
    #print('bin_message  :',message)
    
    # WE Create the sub Keys
    subkey_arr = create_DES_subkeys(key)
    
    # Step 2: Encode each 64-bit block of data.
    # +++++++++++++ Premutate the message++++++++++++++++#
    MM = ''.join(premutate(message,IP))
    
    # Get L0 and R0
    l0 = ''.join(MM[:32])
    r0 = ''.join(MM[32:])
    
    # Get cipher block 
    '''
    Ln = Rn-1
    Rn = Ln-1 + f(Rn-1,Kn)
    '''
    l = l0
    r = r0
    ll = l
    # 16 times loop to cover all the keys
    for i in range(16):
        l = r
        r = bin_xor(ll,f(r,subkey_arr[i]))
        ll =l
    # reverse left and right 32bit blocks
    rl = r+l
    
    # Final cipher is the premutation with IP_inverseall
    final_cipher = ''.join(premutate(rl,IP_inverse))
    
    # Return the bytevalues
    return binary2bytes(final_cipher)
#===========================================================#
############## TEST Func ####################################
from Crypto.Cipher import DES
from random import randint

def cryptodome_DES(Key, Message):
    cipher = DES.new(Key, DES.MODE_ECB)
    msg = cipher.encrypt(Message)
    return msg

def generate_rand_64b():
    rand_64bit = ''.join([bin(randint(0,255))[2:].zfill(8) for i in range(8)])
    return rand_64bit

def are_random_tests_all_passes(tests=10):
    for i in range(tests):
        test_message = binary2bytes(generate_rand_64b())
        test_key     = binary2bytes(generate_rand_64b())

        #print(cryptodome_DES(test_key, test_message), '=', encrypt_DES(test_key,test_message))
        if cryptodome_DES(test_key, test_message) != encrypt_DES(test_key,test_message):
            print('DES encrytption ERROR')
            return False
    print('ALL TESTS PASSED\n')
    return True

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

if __name__ == '__main__':
    
    # BASIC TEST
    #Key = b'\x13\x34\x57\x79\x9b\xbc\xdf\xf1'
    #Message = b'\x01\x23\x45\x67\x89\xab\xcd\xef'
    #encrypt_DES(Key,Message)
    
    # Tests
    print(are_random_tests_all_passes(10000))