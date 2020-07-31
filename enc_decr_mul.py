# MARCEL ISMAEL
# BaseException

# TASK 1
def encrypt_with_mul(string, key):
    '''
    >>> encrypt_with_mul('Hello',227)
    '«£àt_'
    >>> encrypt_with_mul(encrypt_with_mul('Hello',123),123)
    'Hello'
    >>> encrypt_with_mul(encrypt_with_mul('Cryptography',10),10)
    'Cryptography'
    '''

    key_seq = [key]
    ret = ''
    for i in string:
        ret += chr(ord(i) ^ key_seq[-1])
        key_seq.append((key_seq[-1] * 2) % 256)
    return ret


# TASK 2
def encrypt_with_mul2(string, key, operation):

    '''>>> encrypt_with_mul2('Hello',34,'encrypt')
    'j!ä|O'
    >>> encrypt_with_mul2('Hello2',131,'encrypt')
    'Ëc`t_R'
    >>> encrypt_with_mul2(encrypt_with_mul2('Hello',123,'encrypt'),123,'decrypt')
    'Hello'
    >>> encrypt_with_mul2(encrypt_with_mul2('Cryptography',10,'encrypt'),10,'decrypt')
    'Cryptography'
    '''
    # check key value
    if key == 0 or key == 1:
        print('Please enter correct key value')
        return None

    # initial values
    key_seq = [key]
    ret = ''

    for i in range(len(string)):
        key_val = key_seq[-1]

        if key_val == 0 or key_val == 1:
            if operation == 'encrypt':
                key_val = ord(string[i - 1])
            elif operation == 'decrypt':
                key_val = ord(ret[-1])
            else:
                print('Wrong operation')
                return None

        ret += chr(ord(string[i]) ^ key_val)
        key_seq.append((key_seq[-1] * 2) % 256)
    return ret

    ## TASK 3


def swap_every_second_bit(num):
    '''>>> swap_every_second_bit(1)
    2
    >>> swap_every_second_bit(2)
    1
    >>> swap_every_second_bit(4)
    8
    >>> swap_every_second_bit(16)
    32
    >>> bin(swap_every_second_bit(0b1010))
    '0b101'
    >>> bin(swap_every_second_bit(0b01010110))
    '0b10101001'
    '''
    # make binary
    binary = bin(num)[2:]

    # Fill bytes with zeros
    target_length = len(b) + (4 - len(b) % 4) % 4
    binary = list(binary.zfill(target_length))

    for i in range(0, len(binary), 2):
        binary[i], binary[i + 1] = binary[i + 1], binary[i]

    # make integer
    swapped_num = int(''.join(binary), 2)

    return swapped_num


# TASK 4
def break_scheme2(string):
    num_of_e = []
    max_e = 0
    key = 0

    # brutforce the keys with encrypt_with_mul2 function
    for i in range(2, 256):
        # Decrypt every message
        message = encrypt_with_mul2(string, i, 'decrypt')

        # check the number of e and compare
        if message.count('e') > max_e:
            key = i
            plain = message
            max_e = message.count('e')

    # print the plain and the key
    print(plain, '\nThe Key is ', key)

    return plain

encrypt_with_mul('Hello',227)