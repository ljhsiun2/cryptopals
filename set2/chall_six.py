from set2.chall_four import generic_encrypt_ecb, padding_oracle
from set2.chall_three import get_random_int, detect_ecb
import base64, random
from set2.chall_one import pkcs7_pad

from set1.chall_seven import aes_ecb_encrypt_with_key

key = get_random_int(128)

def generic_encrypt_ecb_wrapper(rand_bits, attacker_bits, target, block_size):
    return generic_encrypt_ecb(rand_bits + attacker_bits + target, key, block_size)

rand_prefix = 0
while 1:
    rand_bit_size = random.randint(1, 128)
    if rand_bit_size % 8 == 0:
        rand_prefix = get_random_int(rand_bit_size)
        break

# in chall 4 we blanketly had multiple blocks: here, we should do it systematically to figure out length of random prefix
prefix_len = 0
target = "attack at dawnBBBBBBBBBBBBBBBBB".encode().hex()
my_string = ''
for i in range(32, 48):
    my_string = ("A"*i).encode().hex()
    #my_string = "YELLOW_SUBMARINE".encode().hex()
    ciphertext = generic_encrypt_ecb_wrapper(rand_prefix, my_string, target, 16)
    dup_blocks = detect_ecb(ciphertext)
    if dup_blocks:
        prefix_len = i - 32
        print(f"Padded {prefix_len} bytes to prefix with duplicate blocks {dup_blocks}")
        break

# from here, should be just the same as 12
block_size = 16
msg = rand_prefix + ("A"*prefix_len).encode().hex()
decrypted_blocks = ''.join([ padding_oracle(target[i:i+block_size*2], block_size, '') for i in range(0, len(target), block_size*2) ])
padding = ord(decrypted_blocks[-1])
decrypted_blocks = decrypted_blocks[:-padding]

print(decrypted_blocks)
assert decrypted_blocks.encode().hex() == target

