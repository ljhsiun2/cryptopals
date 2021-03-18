from set1.chall_seven import aes_ecb_encrypt_with_key
from set1.chall_two import xor_hex_strings
from base64 import b64decode
from struct import pack

# inputs are all hex
# outputs are also all hex
def aes_ctr_operation(key, data, nonce):
    ctr_output = ''
    ctr = 0
    block = data[ctr*32:(ctr+1)*32]

    while block:
        ctr_data = pack('<QQ', int(nonce, 16), ctr)      # see struct library for packing formatting
        aes_out = aes_ecb_encrypt_with_key(ctr_data, bytes.fromhex(key))

        temp_output = xor_hex_strings(aes_out[0].hex()[:len(block)], block)
        if len(temp_output) % 2: temp_output = '0' + temp_output

        ctr_output += temp_output

        ctr += 1
        block = data[ctr*32:(ctr+1)*32]

    return ctr_output


def main():
    msg = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = "YELLOW SUBMARINE"
    nonce = b'\x00'

    plaintext =  aes_ctr_operation(key.encode().hex(), msg.hex(), nonce.hex())
    ciphertext = aes_ctr_operation(key.encode().hex(), plaintext, nonce.hex())

    assert bytes.fromhex(ciphertext) == msg

    msg = "lawl xd i'm n0t creative why do i do these challenges at 2am"
    key = "YELLOW SUBMARINE"
    nonce = b'peekaboo'

    ciphertext = aes_ctr_operation(key.encode().hex(), msg.encode().hex(), nonce.hex())
    plaintext  = aes_ctr_operation(key.encode().hex(), ciphertext, nonce.hex())

    assert msg.encode() == bytes.fromhex(plaintext)
    print(bytes.fromhex(plaintext), bytes.fromhex(ciphertext))

if __name__ == '__main__':
    main()
