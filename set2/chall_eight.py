from set2.chall_seven import pkcs7_unpad
from set2.chall_two import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
import urllib.parse

key = get_random_int(128)
iv = get_random_int(128)
block_size = 16

def encryption_oracle(input_string):
    input_string = urllib.parse.quote(input_string)
    plaintext = '"comment1"="cooking%20MCs";"userdata"="' + input_string + '";"comment2"="%20like%20a%20pound%20of%20bacon"'
    return cbc_encrypt(plaintext.encode().hex(), key, iv)

def decryption_oracle(ciphertext):
    plaintext = bytes.fromhex(cbc_decrypt(ciphertext, key, iv))
    normal_plaintext = pkcs7_unpad(plaintext)
    cookie_data = normal_plaintext.split(b';')
    for data in cookie_data:
        try:
            (pt_key, value) = (data.split(b'=')[0], data.split(b'=')[1])
            if b"admin" == pt_key:
                return (pt_key, value)
        except IndexError:
            pass
    return 0

# xors single byte in hex string with value
def xor_single_byte(hex_one, value, byte_num):
    temp = bytearray.fromhex(hex_one)
    temp[byte_num] ^= value
    return bytes(temp).hex()

def inject_string_cbc(ciphertext, injection_string, start_pos):
    ret_cipher = ciphertext
    for i in range(0, len(injection_string)):
        value = ord(injection_string[i]) ^ 65
        ret_cipher = xor_single_byte(ret_cipher, value, start_pos + i)
    return ret_cipher

injection_string = '";admin=true;'
input_string = "testAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
ciphertext = encryption_oracle(input_string)
print(decryption_oracle(ciphertext))
#ciphertext2 = xor_single_byte(ciphertext, 99, 64)

injected_ciphertext = inject_string_cbc(ciphertext, injection_string, 64)
decrypted_text = decryption_oracle(injected_ciphertext)
print(decrypted_text)

assert b'admin' in decrypted_text




