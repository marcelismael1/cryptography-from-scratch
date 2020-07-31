# Marcel Ismael
# Hashes
# Mon 27-04-2020


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
import hashlib

def sha256(string):
    '''
    >>> sha256('I')
    'a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c'
    >>> sha256('love')
    '686f746a95b6f836d7d70567c302c3f9ebb5ee0def3d1220ee9d4e9f34f5e131'
    >>> sha256('crypto')
    'da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4'
    '''
    res = hashlib.sha256(string.encode()).hexdigest()
    return res


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
users = {
    'admin':'8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', #sha256('admin')
    'user':'2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', #sha256('hello')
}

def authenticate(user, password):
    '''
    >>> authenticate('admin','admin')
    True
    >>> authenticate('admin','admin2')
    False
    >>> authenticate('user','hello')
    True
    >>> authenticate('user','helo')
    False
    '''
    if user in users.keys():
        return sha256(password) == users[user]
    else:
        return False

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
def hack_sha256_fixed_size(hash_val ,  char_count):
    
    '''
    >>> hack_sha256_fixed_size('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',5)
    'admin'
    >>> hack_sha256_fixed_size('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',5)
    'hello'
    >>> hack_sha256_fixed_size('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b',5)
    'crypt'
    >>> hack_sha256_fixed_size('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6',3)
    'asd'
    >>> hack_sha256_fixed_size('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214',4)
    'elte'
    '''
    chars = 'abcdefghijklmnopqrstuvxyz'
    # Brute force algorithm from 
    # https://stackoverflow.com/questions/11747254/python-brute-force-algorithm
    a = list(chars)
    for y in range(char_count-1):
        a = [x+i for i in chars for x in a]
    # End of algorithm 
    
    for i in a:
        if sha256(i) == hash_val:
            return i
    else:
        return None

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
def hack_sha256(hash_val):
    '''
    >>> hack_sha256('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918')
    'admin'
    >>> hack_sha256('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    'hello'
    >>> hack_sha256('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b')
    'crypt'
    >>> hack_sha256('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6')
    'asd'
    >>> hack_sha256('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214')
    'elte'
    '''
    for i in range(10):
        value = hack_sha256_fixed_size(hash_val,i)
        if  value != None:
            return value 
    else:
        return None

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#
# Longer example
# I used Crack station website which uses the concept of Rainbow attack to genertated pre computed hashes
# https://crackstation.net/
# CrackStation uses massive pre-computed lookup tables to crack password hashes.
# These tables store a mapping between the hash of a password, and the correct password for that hash. 
# The hash values are indexed so that it is possible to quickly search the database for a given hash.
'''
e06554818e902b4ba339f066967c0000da3fcda4fd7eb4ef89c124fa78bda419
'cryptography'

8aa261cbc05ad6a49bea91521e51c8b979aa78215b8defd51fc0cebecc4d5c96
'romeo and juliet'

f2b826b18b9de86628dd9b798f3cb6cfd582fb7cee4ea68489387c0b19dc09c1
'vulnerable'
'''

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
users_with_pepper = {
    'admin':{'passwordHash':'89e6b5ed137e3864d99ec9b421cf6f565d611f4c2b98e31a7d353d63aa748e9c'}, #sha256('this_can_help_to_confuse_the_attacker_admin')
    'user': {'passwordHash':'6dc765830e675d5fa4a9afb248be09a0407f6353d44652fd9b36038884a76323'}, #sha256('this_can_help_to_confuse_the_attacker_hello')
}
def authenticate_with_pepper(user, password):
    '''
    >>> authenticate_with_pepper('admin','admin')
    True
    >>> authenticate_with_pepper('admin','admin2')
    False
    >>> authenticate_with_pepper('user','hello')
    True
    >>> authenticate_with_pepper('user','helo')
    False
    '''
    if user in users.keys():
        return sha256(pepper_prefix+password) == users_with_pepper[user]['passwordHash']
    else:
        return False

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++#

pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
users_with_pepper_and_salt = {
    'admin':{'passwordHash':'d3eab7f4d6974f1db32b9cd9923fce9b434b28dc229b6582b845f1fca770d9f7','salt':"5294976873732394418"}, #sha256('this_can_help_to_confuse_the_attacker_admin5294976873732394418')
    'user': {'passwordHash':'976c73e0b408c89df3c1a12c3b0c45a6fee71bc1de5b47a88fae1a5e69ba6e28','salt':'1103733363818826232'}, #sha256('this_can_help_to_confuse_the_attacker_hello1103733363818826232')
}

def authenticate_with_pepper_and_salt(user,password):
    '''
    >>> authenticate_with_pepper_and_salt('admin','admin')
    True
    >>> authenticate_with_pepper_and_salt('admin','admin2')
    False
    >>> authenticate_with_pepper_and_salt('user','hello')
    True
    >>> authenticate_with_pepper_and_salt('user','helo')
    False
    '''
    password_with_salt_pepper = pepper_prefix+password+users_with_pepper_and_salt[user]['salt']
    if user in users.keys():
        return sha256(password_with_salt_pepper) == users_with_pepper_and_salt[user]['passwordHash']
    else:
        return False

#==================================================================================================#
#==================================================================================================#

