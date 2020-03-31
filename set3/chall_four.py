from set1.chall_six import *
from set1.chall_three import xor_single_byte
from set1.chall_two import xor_hex_strings
from set2.chall_three import get_random_int
from set3.chall_two import aes_ctr_operation

key = get_random_int(128)
nonce = get_random_int(64)
ciphertexts = []

def encrypt_lines(lines):
    for pt in lines:
        msg = base64.b64decode(pt.strip())
        ciphertexts.append(aes_ctr_operation(key, msg.hex(), nonce))

# code ripped from set1.chall_six
# I definitely could've made this a function in six... but I didn't
def main():
    with open('20.txt', 'r') as f:

        plaintext = f.readlines()
        encrypt_lines(plaintext)
        #print(ciphertexts)
        block_len = len(min(ciphertexts, key=len))
        blocks = [ ctext[:block_len] for ctext in ciphertexts ]

        potential_keys = []
        transposed_blocks = transpose_blocks(bytes.fromhex(''.join(blocks)), int(block_len/2))

        #print(f"\n------\nUsing KEYSIZE = {key_sz}\n------")
        probable_key = ''
        for block in transposed_blocks:
            block_hex = bytes([ord(c) for c in block]).hex()
            #print(block, block_hex)
            #print( xor_single_byte(block.encode()) )
            (decrypted_str, score, key_byte) = xor_single_byte(block_hex)
            if score != 0:
               probable_key += chr(key_byte)


        if block_len/2 == len(probable_key):
            potential_keys.append(probable_key)

        print(f"\nProbable key is \"{potential_keys}\"\n\n")

        # TODO: currently only decrypts the first <shortest-length-ciphertext> chars of every line since that's what challenge says
        # the rest of the string could be decrypted by simply finding the next shortest string and
        # continuing based off that length, but the concept here should already be clear enough.
        probable_key = bytes([ord(c) for c in probable_key]).hex()
        dec_message = [bytes.fromhex(xor_hex_strings(probable_key, block)).decode() for block in blocks]

        for i in range(len(dec_message)):
            assert dec_message[i].encode().hex() == base64.b64decode(plaintext[i])[:53].hex()

if __name__ == '__main__':
    main()
    print("passed challenge four!")


