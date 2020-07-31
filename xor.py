
def hex2string(h):
    r = ''.join([chr(int(h[i:i+2],16)) for i in range(0,len(h),2)])
    return r
    
def string2hex(st):
    return ''.join([hex(ord(i))[2:] for i in st])

def hex_xor(h1,h2):
    if h1==h2:
        return '0'*len(h1)
    else:
        return hex(int(h1,16)^int(h2,16))[2:]
    

def encrypt_single_byte_xor(a,b):
    return ''.join([hex_xor(a[i:i+2],b) for i in range(0,len(a),2)])
    

message= 'e9c88081f8ced481c9c0d7c481c7ced4cfc581ccc480'
for i in range (256):
    print (hex2string(encrypt_single_byte_xor(message,hex(i))),'   ', hex(i)[2:])