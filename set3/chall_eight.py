from set3.chall_five import *
from set3.chall_six import *
from set2.chall_three import get_random_int
from set1.chall_two import xor_hex_strings
import random
import string

def init_seed(seed):
    seed_mt(int(seed, 16))

def encrypt(key, msg):

    init_seed(key)
    keystream = ''

    while len(keystream) < len(msg):
        keystream += format(extract_number(), '08x')

    keystream = keystream[:len(msg)]
    return xor_hex_strings(keystream, msg)

def decrypt(key, ciphertext):
    return encrypt(key, ciphertext)

def find_16b_mt19937_key(known_plaintext, ciphertext):

    known_plaintext_hex = known_plaintext.encode().hex()

    for guessed_key in range(2**16):
        if known_plaintext_hex in decrypt(format(guessed_key, '032x'), ciphertext):
            return guessed_key

    raise ValueError("Could not find 16bit key; error in setting key?")



def main():
    key = get_random_int(16)
    msg = "attack at dawn"
    prefix = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(random.randint(0, 100))])

    crafted_msg = prefix + msg

    ciphertext = encrypt(key, crafted_msg.encode().hex())
    plaintext = decrypt(key, ciphertext)
    assert plaintext == crafted_msg.encode().hex()
    print("Encryption/decryption work correctly")

    guessed_key = find_16b_mt19937_key("attack at dawn", ciphertext)
    print(guessed_key)
    assert guessed_key == int(key, 16)

    # Now get current time and restrict it to 16 bits
    import time
    current_time = int(time.time()) % (2 ** 16)
    seed_mt(current_time)
    reset_token = extract_number()
    msg = "password_reset="+str(reset_token)

    from set3.chall_six import get_mt_seed
    prev_time = get_mt_seed(int(time.time()) % (2**16), reset_token)
    seed_mt(prev_time)
    assert reset_token == extract_number()
    print("Reset token found!")


if __name__ == '__main__':
    main()
    print("set 3 challenge 8 complete!")
