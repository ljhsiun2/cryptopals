from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def aes_ecb_encrypt_with_key(plaintext, key):
    CipherObj = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend() )
    encryptor = CipherObj.encryptor()
    return (encryptor.update(plaintext) + encryptor.finalize(), CipherObj)

def aes_ecb_decrypt(CipherObj, ciphertext):
    decryptor = CipherObj.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def main():
    with open('7.txt', 'r') as f:
        ciphertext = base64.b64decode( f.read().strip() )
        key = b"YELLOW SUBMARINE"
        CipherObj = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend() )
        dt = aes_ecb_decrypt(CipherObj, ciphertext)
        print(dt)

if __name__ == '__main__':
    main()
