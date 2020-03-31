from set1.chall_seven import aes_ecb_encrypt_with_key
from set1.chall_two import xor_hex_strings
from set1.chall_three import score_string
from base64 import b64decode
from set3.chall_two import aes_ctr_operation
from set2.chall_three import get_random_int

aes_key = get_random_int(128)
nonce = b'\x00'
ciphertext_array = []



def guess_full_key(ciphertext):
    key_bytes = bytearray([0]*16)
    for i in range(0, len(key_bytes), 3):
        temp_score = 0
        best_score = -9999999
        best_byte1 = 0
        best_byte2 = 0
        best_byte3 = 0
        for j in range(256):
            key_bytes[i] = j
            for k in range(256):
                key_bytes[i+1] = k
                for l in range(256):
                    key_bytes[i+2] = l
                    plaintext = aes_ctr_operation(key_bytes.hex(), ciphertext, nonce.hex())
                    if len(plaintext) % 2:
                        plaintext = '0' + plaintext
                    temp_score = score_string(bytes.fromhex( plaintext[2*i:2*(i+3)] ))
                    if temp_score > best_score:
                        print(bytes.fromhex(plaintext))
                        (best_score, best_byte1, best_byte2, best_byte3) = (temp_score, j, k, l)
        key_bytes[i] = best_byte1
        key_bytes[i+1] = best_byte2
        key_bytes[i+2] = best_byte3


# encryption
with open('19.txt', 'r') as f:
    for line in f:
        plaintext = b64decode(line.strip())
        ciphertext_array.append( aes_ctr_operation(aes_key, plaintext.hex(), nonce.hex()) )

print(ciphertext_array)

for ctext in ciphertext_array:
    guess_full_key(ctext)
