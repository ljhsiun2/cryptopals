from set2.chall_seven import pkcs7_unpad
from set2.chall_two import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
import urllib.parse

key = get_random_int(128)
iv = key
block_size = 16

print(key, iv)

def encryption_oracle(input_string):
    input_string = urllib.parse.quote(input_string)
    plaintext = '"comment1"="cooking%20MCs";"userdata"="' + input_string + '";"comment2"="%20like%20a%20pound%20of%20bacon"'
    return cbc_encrypt(plaintext.encode().hex(), key, iv)

def decryption_oracle(ciphertext):
    plaintext = bytes.fromhex(cbc_decrypt(ciphertext, key, iv))

    for c in plaintext:
        if c > 127:
            print(f"bad ASCII plaintext: {plaintext}")
            return plaintext

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

if __name__ == '__main__':
    msg = ''

    ciphertext = encryption_oracle('')
    crafted_ciphertext = ciphertext[:32] + '0'*32 + ciphertext[:32]
    print(crafted_ciphertext)
    plaintext = decryption_oracle(crafted_ciphertext)

    derived_key = ''
    for i in range(16):
        derived_key += hex(plaintext[i] ^ plaintext[i + 32])[2:].zfill(2)

    assert derived_key == key
    assert derived_key == iv


