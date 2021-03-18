from set3.chall_two import aes_ctr_operation
from set2.chall_three import get_random_int
from set1.chall_seven import aes_ecb_decrypt
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = get_random_int(128)
nonce = b"\x00"

def edit(ciphertext, offset, newtext):
    decrypted_text = aes_ctr_operation(key, ciphertext, nonce.hex())

    len_newtext = len(newtext)
    crafted_plaintext = decrypted_text[:offset] + newtext + decrypted_text[offset+len_newtext:]

    ciphertext = aes_ctr_operation(key, crafted_plaintext, nonce.hex())
    return ciphertext

def main():

    # code taken from 1.7
    dt = ''
    with open('25.txt', 'r') as f:
        ciphertext = base64.b64decode( f.read().strip()  )
        chall_seven_key = "YELLOW SUBMARINE"
        CipherObj = Cipher(algorithms.AES(chall_seven_key.encode()), modes.ECB(), backend=default_backend() )
        dt = aes_ecb_decrypt(CipherObj, ciphertext)

    ciphertext = aes_ctr_operation(key, dt.hex(), nonce.hex())
    ciphertext_bytes = bytes.fromhex(ciphertext)

    # begin "attack" here
    injected_text = "A"*int(len(ciphertext)/2)
    injected_ciphertext = edit(ciphertext, 0, injected_text.encode().hex())
    injected_bytes = bytes.fromhex(injected_ciphertext)

    assert len(ciphertext_bytes) == len(injected_bytes)
    extracted_plaintext = ''
    for i in range(len(injected_bytes)):
        extracted_plaintext += chr(injected_bytes[i] ^ ord("A") ^ ciphertext_bytes[i])

    print(extracted_plaintext)


if __name__ == '__main__':
    main()
