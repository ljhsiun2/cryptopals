from set1.chall_seven import *
from set1.chall_two import xor_hex_strings
from set2.chall_one import pkcs7_pad
import base64
import codecs

block_size = 16

def cbc_encrypt(msg, key, iv):

    # check that msg == hex, key == hex, iv == hex
    # I should probably handle these better but whatever
    assert int(msg, 16)
    assert int(key, 16)
    assert int(iv, 16)

    padded_msg = pkcs7_pad(msg, block_size)
    msg_blocks = [ padded_msg[i:(i+block_size*2)] for i in range(0, len(padded_msg), block_size*2) ]

    iv_first_block = xor_hex_strings(iv, msg_blocks[0])

    (block_0, encryptor) = aes_ecb_encrypt_with_key(bytes.fromhex(iv_first_block), bytes.fromhex(key))
    block_i = block_0
    ctext = [block_i.hex()]
    for msg_block in msg_blocks:
        iv_i = xor_hex_strings(block_i.hex(), msg_block)
        (block_i, encryptor) = aes_ecb_encrypt_with_key(bytes.fromhex(iv_i), bytes.fromhex(key))
        ctext.append(block_i.hex())

    return ''.join(ctext)

def cbc_decrypt(ciphertext, key, iv):
    ctext_blocks = [ ciphertext[i:(i+block_size*2)] for i in range(0, len(ciphertext), block_size*2) ]

    CipherObj = Cipher(algorithms.AES(bytes.fromhex(key)), modes.ECB(), backend=default_backend() )
    iv_i = iv

    decrypted_text = []
    for ctext in ctext_blocks:
        d_i = aes_ecb_decrypt(CipherObj, bytes.fromhex(ctext)).hex()
        decrypted_text.append(xor_hex_strings(iv_i, d_i))
        iv_i = ctext

    return ''.join(list(dict.fromkeys(decrypted_text)))

#with open('10.txt', 'rb') as f:
#    iv = '\x00'*block_size
#    iv = iv.encode().hex()
#    key = 'YELLOW SUBMARINE'.encode().hex()
#    test_msg = "testtttt".encode().hex()
#    ciphertext = cbc_encrypt(test_msg, key, iv)
#    plaintext = cbc_decrypt(ciphertext, key, iv)
#    assert plaintext == pkcs7_pad(test_msg, block_size)
#
#    msg = f.read()
#    msg = base64.b64decode(msg).hex()
#    plaintext = cbc_decrypt(msg, key, iv)
#    print(bytes.fromhex(plaintext).decode())
#


