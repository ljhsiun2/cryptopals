from set2.chall_one import pkcs7_pad
from set2.chall_two   import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
from set2.chall_seven import pkcs7_unpad
import base64, random

encoded_array = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
        ]

oracle_key =  get_random_int(128)
oracle_iv =   get_random_int(128)
rand_msg = encoded_array[random.randint(0, 9)]

def encryption_oracle(msg):
    return (cbc_encrypt(msg, oracle_key, oracle_iv), oracle_iv)

def decryption_oracle(ciphertext, iv):

    plaintext = cbc_decrypt(ciphertext, oracle_key, iv)
    try:
        unpadded_data = pkcs7_unpad(bytes.fromhex(plaintext))
        return True
    except:
        return False

# 1) find ciphertext byte that yields 0x1 padding
#   - i.e. c_{n-1}[i] ^ OUT[i] = 0x1
#   - can brute force
# TODO make multiple byte attempts, not just first one encountered

def decrypt_byte(block, iv, i):
    aes_out_bytes = []
    iv_bytes = iv
    for j in range(0, 256):
        iv_bytes[-i] = j
        if decryption_oracle(block, iv_bytes.hex()):
            #print("Found! " + iv_bytes.hex())
            # j ^ i == aes_out_byte for j = injected byte, i = padding detetcted
            # aes_out_byte ^ init_byte == init_plaintext
            aes_out_bytes.append( ((j ^ i), j) )

    return aes_out_bytes



def decrypt_block(block, iv):

    iv_bytes = bytearray.fromhex(iv)
    plaintext = ''
    aes_out_bytes = []
    initial_bytes = []

    iv_bytes_temp = iv_bytes
    aes_out_bytes_temp = []
    i = 1
    while i < 17:
        initial_byte = iv_bytes[-i]
        aes_out_bytes_temp = decrypt_byte(block, iv_bytes, i)

        if len(aes_out_bytes_temp) > 1:
            for aes_byte, iv_byte in aes_out_bytes_temp:
                iv_bytes_temp[-i] = aes_byte ^ ( i + 1 )
                test2 = decrypt_byte(block, iv_bytes_temp, i+1)
                if len(test2) > 0:
                    aes_out_bytes.append(aes_byte)
                    aes_out_bytes.append(test2[0][0])
                    initial_bytes.append(initial_byte)
                    initial_bytes.append(bytearray.fromhex(iv)[-i-1])
                    #plaintext += chr(aes_out_bytes[i-1] ^ initial_byte)
                    #initial_byte = iv_byte
                    i += 1
                    break

        else:
            aes_out_bytes.append(aes_out_bytes_temp[0][0])
            initial_bytes.append(initial_byte)


        #plaintext += chr(aes_out_bytes[i-1] ^ initial_byte)

        for k in range(1, i+1):
            iv_bytes_temp[-k] = aes_out_bytes[k-1] ^ (i + 1) # now pad to next byte
        #print(iv_bytes, iv_bytes.hex(), iv)

        aes_out_bytes_temp = []
        iv_bytes = iv_bytes_temp
        i += 1

    plaintext = ''.join([ chr(aes_out_bytes[i-1] ^ initial_bytes[i-1]) for i in range(1, 17) ])
    return plaintext[::-1]


def apply_injections(ciphertext, iv):
    ctext_blocks = [ ciphertext[i:(i+32)] for i in range(0, len(ciphertext), 32) ]
    crafted_ciphertext = ''
    decrypted_text = ''
    # find init plaintext block
    #plaintext = decrypt_block(ctext_blocks[0], iv)
    plaintext = ''

    for i in range(1, len(ctext_blocks)):
        plaintext += decrypt_block(ctext_blocks[i], ctext_blocks[i-1])

    return plaintext


# brief sanity check that encryption and decryption work
def main():
    print( base64.b64decode(rand_msg))
    (ciphertext, iv) = encryption_oracle(base64.b64decode(rand_msg).hex())
    assert True == decryption_oracle(ciphertext, iv)

    plaintext = apply_injections(ciphertext, iv)
    unpadded_plaintext = pkcs7_unpad(plaintext.encode())

    print(f"Plaintext is \t\t{plaintext.encode()}\nUnpadded is \t\t{unpadded_plaintext}\n\n\n\n")

    assert unpadded_plaintext == base64.b64decode(rand_msg)

if __name__ == '__main__':
    main()


