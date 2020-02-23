from chall_two import xor_hex_strings
from math import ceil

def xor_encrypt_string(plaintext, key):
    # need to pad key, and cut key, for proper xor-ing. Only works if key.len < plaintext.len
    padded_key = key*( ceil( len(plaintext)/len(key) ) )
    if len(padded_key) > len(plaintext):
        padded_key = padded_key[:len(plaintext)]
    # assuming the plaintext and key are in hex
    hex_plain = plaintext.encode().hex()
    hex_key = padded_key.encode().hex()
    return xor_hex_strings(hex_plain, hex_key)

#plaintext = """Burning 'em, if you ain't quick and nimble
#I go crazy when I hear a cymbal"""
#key = "ICE"
#print( xor_encrypt_string(plaintext, key)[2:] )
