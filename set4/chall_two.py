from set2.chall_seven import pkcs7_unpad
from set2.chall_one import pkcs7_pad
from set2.chall_three import get_random_int
from set3.chall_two import aes_ctr_operation
import urllib.parse

key = get_random_int(128)
nonce = get_random_int(64)
block_size = 16

def encryption_oracle(input_string):
    input_string = urllib.parse.quote(input_string)
    plaintext = '"comment1"="cooking%20MCs";"userdata"="' + input_string + '";"comment2"="%20like%20a%20pound%20of%20bacon"'
    plaintext = pkcs7_pad(plaintext.encode().hex(), block_size)
    return aes_ctr_operation(key, plaintext, nonce)

def decryption_oracle(ciphertext):
    plaintext = bytes.fromhex(aes_ctr_operation(key, ciphertext, nonce))
    print(plaintext)
    normal_plaintext = pkcs7_unpad(plaintext)
    #print(plaintext)
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
def replace_byte_at_pos(hex_one, value, byte_num):
    temp = bytearray.fromhex(hex_one)
    temp[byte_num] = value
    return bytes(temp).hex()

def inject_string_at_pos(ciphertext, injection_string, start_pos, keystream):
    ret_ct = ciphertext
    for i in range(0, len(injection_string)):
        value = ord(injection_string[i]) ^ ord(keystream[i])
        ret_ct = replace_byte_at_pos(ret_ct, value, start_pos + i)

    return ret_ct

def main():
    injection_string = '";admin=true;'
    input_string = "nothinggggggg to see here!"
    ciphertext = encryption_oracle(input_string)
    ciphertext_bytes = bytes.fromhex(ciphertext)

    # find position of where string is injected
    ciphertext_empty = encryption_oracle("")
    diffs = [i for i in range(len(ciphertext_empty)) if ciphertext[i] != ciphertext_empty[i]]
    start_pos = int(diffs[0]/2)

    #for i in range(len(input_string)):
    #    print(input_string[i])
    #    print(ciphertext_bytes[start_pos+i])
    #    print(ord(input_string[i]))
    keystream = [chr( ord(input_string[i]) ^ ciphertext_bytes[start_pos + i]) for i in range(len(input_string))]
    print(keystream)

    crafted_ct = inject_string_at_pos(ciphertext, injection_string, start_pos, keystream)
    print(ciphertext+'\n')
    print(crafted_ct)

    assert b'true' in decryption_oracle(crafted_ct)

if __name__ == '__main__':
    main()
