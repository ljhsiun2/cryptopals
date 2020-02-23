from set2.chall_three import get_random_int, detect_ecb
import base64
from set2.chall_one import pkcs7_pad

from set1.chall_seven import aes_ecb_encrypt_with_key

key = get_random_int(128)

def generic_encrypt_ecb(msg, key, block_size):
    (ciphertext, CipherObj) = aes_ecb_encrypt_with_key( bytes.fromhex(pkcs7_pad(msg, block_size)), bytes.fromhex(key) )
    return ciphertext.hex()

def find_cipher_block_size(unknown_string):
    padded_lengths = []
    for i in range(0, 64):
        rand_str = ("A"*i).encode().hex()
        try:
            (ciphertext, CipherObj) = aes_ecb_encrypt_with_key( bytes.fromhex(rand_str + unknown_string), bytes.fromhex(key) )
            padded_lengths.append(i)
        except ValueError:
            pass #print(f"Invalid block length {i}; trying next length")
    return padded_lengths

def padding_oracle(unknown_hex, block_size, prefix):
    # added "prefix" arg to make challenge six easier

    decrypted_string = ''
    for i in range(0, block_size):
        my_string = ("A"*(block_size - 1- i)).encode().hex()
        ciphertext = generic_encrypt_ecb(prefix + my_string + unknown_hex, key, block_size)
        ciphertext_model = ciphertext[len(prefix):len(prefix)+block_size]
        for j in range(0, 255):
            my_string_padded = my_string + decrypted_string.encode().hex() + chr(j).encode().hex()
            ciphertext = generic_encrypt_ecb(prefix + my_string_padded + unknown_hex, key, block_size)
            if ciphertext[len(prefix):len(prefix)+block_size] == ciphertext_model:
                decrypted_string += chr(j)
                break

    return decrypted_string


def chall_four(unknown_string):
    unknown_hex = base64.b64decode(unknown_string).hex()

    found_block_sizes = find_cipher_block_size(unknown_hex)
    block_size = found_block_sizes[1] - found_block_sizes[0]
    my_string = ("A"*block_size*3).encode().hex() # want to pad >2 block lengths to detect repetition (i.e. force message to have 2 equivalent blocks)

    padded_msg = pkcs7_pad(my_string + unknown_hex, block_size)
    (ciphertext, CipherObj) = aes_ecb_encrypt_with_key( bytes.fromhex(padded_msg), bytes.fromhex(key))
    ciphertext = ciphertext.hex()
    ecb_detected = detect_ecb(ciphertext)
    if not ecb_detected:
        print("ECB not detected; not exploitable")
        return

    # now we know the block size, and it's in ECB
    decrypted_blocks = ''.join([ padding_oracle(unknown_hex[i:i+block_size*2], block_size, '') for i in range(0, len(unknown_hex), block_size*2) ])

    #unpad string
    padding = ord(decrypted_blocks[-1])
    decrypted_blocks = decrypted_blocks[:-padding]

    return decrypted_blocks

unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

decrypted_text = chall_four(unknown_string)
assert decrypted_text == base64.b64decode(unknown_string).decode()
