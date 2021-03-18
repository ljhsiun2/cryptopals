from set4.sha1 import pad_msg
import struct

key = b'YELLOW SUBMARINE'
with open('/usr/share/dict/words', 'r') as word_file:
    import random
    words = word_file.readlines()
    key = words[random.randrange(0, len(words)-1)].encode()

def md4(hexmsg, msg_len=0, a=0x67452301, b=0xefcdab89, c=0x98badcfe, d=0x10325476):

    byte_msg = pad_msg(hexmsg, msg_len)
    msg_blocks = [ byte_msg[i:(i+64)] for i in range(0, len(byte_msg), 64) ]

    for block in msg_blocks:


def md4_mac(key, msg):
    return md4_model(key+msg, len(key+msg)*8)[2:].zfill(32)

def validate_mac(msg, input_hash):
    oracle_mac = md4_mac(key, msg)
    #assert oracle_mac == input_hash, "invalid MAC, hack attempted!"
    if oracle_mac != input_hash:
        return 0
    else:
        return 1

def length_extension(known_msg, inject_data, original_hash):

    for guess_key_len in range(128):
        # use the same padding in sha1, but just chop the key/suffix
        # since key will just get "added back" in the oracle
        crafted_msg = pad_msg(b"A"*guess_key_len + known_msg.encode(), (guess_key_len + len(known_msg))*8)[guess_key_len:] + inject_data

        (a, b, c, d) = struct.unpack('>4I', bytes.fromhex(original_hash))
        forged_mac = md4_model(inject_data, (guess_key_len + len(crafted_msg))*8, a, b, c, d)[2:]
        if validate_mac(crafted_msg, forged_mac):
            return forged_mac, crafted_msg

    raise ValueError("length extension failed")



def main():
    known_msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    inject_data = b';admin=true'

    orig_hash = md4_mac(key, known_msg.encode()).decode()
    print(orig_hash)
    new_mac, cookie = length_extension(known_msg, inject_data, orig_hash, md4_model, validate_mac)

    assert b'admin' in cookie
    print(f"successful length extension! new mac: {new_mac}\nold mac: {orig_hash}\ncookie: {cookie}")

if __name__ == "__main__":
    main()
