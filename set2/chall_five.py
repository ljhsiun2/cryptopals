from set2.chall_three import get_random_int
import json

from set2.chall_one import pkcs7_pad

from set1.chall_seven import aes_ecb_encrypt_with_key, aes_ecb_decrypt


key = get_random_int(128)


def add_cookie_to_json(input_string, input_dict):
    params = input_string.split("&")
    for param in params:
        (key, value) = (param.split("=")[0], param.split("=")[1])
        if key == "role":
            assert value != "admin"
        input_dict[key] = value

def profile_for(input_string, input_dict):
    # expected format: foo@bar.com
    rand_int = 10
    formatted_cookie = f"email={input_string}&uid={rand_int}&role=user"
    add_cookie_to_json(formatted_cookie, my_dict)

def encrypt_profile(input_string):
    padded_string = pkcs7_pad(input_string.encode().hex(), 16)
    return aes_ecb_encrypt_with_key(bytes.fromhex(padded_string), bytes.fromhex(key))

def decrypt_profile(ciphertext, CipherObj):
    return aes_ecb_decrypt(CipherObj, ciphertext)


# json format: {"email": "<email>", "uid": "10", "role": "user"}
# attacker knows: ciphertext, and format of plaintext (but in a real scenario, UID might be more randomized)

my_dict = {}
email = "foo@bar.comAAAAAAAAAA" + bytes.fromhex(pkcs7_pad('"admin"}'.encode().hex(), 16)).decode()
profile_for(email, my_dict)
(ciphertext, CipherObj) = encrypt_profile(json.dumps(my_dict))

# cut off first two bytes (email) to get admin ciphertext
admin_ciphertext = ciphertext[32:48]

# 2) pad "admin" ciphertext onto encrypted cookie such that ciphertext ends in "role="

my_dict = {}
email = "foo@barLOL.co"
profile_for(email, my_dict)
(ciphertext, CipherObj) = encrypt_profile(json.dumps(my_dict))

# cut first 48 bytes and append with step 1 ciphertext; 48 = length of formatted json
plaintext = decrypt_profile(ciphertext[:48] + admin_ciphertext, CipherObj)

print(plaintext.decode())
assert "admin" in plaintext.decode()
assert email in plaintext.decode()
