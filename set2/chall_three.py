import random
from set2.chall_one import pkcs7_pad
from set1.chall_seven import aes_ecb_encrypt_with_key
from set2.chall_two import cbc_encrypt

def get_random_int(size):
    while 1:
        ret_bits = hex(random.getrandbits(size))[2:]
        if len(ret_bits) == size/4: return ret_bits
        # of course, don't use this for security :) https://en.wikipedia.org/wiki/Mersenne_Twister#Disadvantages

def encryption_oracle(msg):
    rand_count = random.randint(5, 10)
    prepad_msg = get_random_int(rand_count*8) + msg.encode().hex() + get_random_int(rand_count*8)
    padded_msg = pkcs7_pad(prepad_msg.encode().hex(), 16)
    #print(padded_msg)

    ciphertext = ''
    key = get_random_int(128)
    iv = get_random_int(128)

    if random.getrandbits(1):
        ciphertext = cbc_encrypt(padded_msg, key, iv)
    else:
        (ciphertext, CipherObj) = aes_ecb_encrypt_with_key(bytes.fromhex(padded_msg), bytes.fromhex(key))
        ciphertext = ciphertext.hex()

    return ciphertext

def detect_ecb(ciphertext):
    hexbytes = bytes.fromhex(ciphertext)
    blocks = [hexbytes[i:(i+16)].hex() for i in range(0, len(hexbytes), 16)]
    set_blocks = set(blocks)
    if len(set_blocks) != len(blocks):
        dup_arr = []
        for block in blocks:
            if block in set_blocks:
                set_blocks.remove(block)
            elif block not in set_blocks:
                if block not in dup_arr:
                    dup_arr.append(block)
        return dup_arr
    else: return []

def chall_three():
    msg = "A"*(16*2+10)
    ciphertext = encryption_oracle(msg)
    return detect_ecb(ciphertext)

print(f"Detected ECB: {chall_three()}")


