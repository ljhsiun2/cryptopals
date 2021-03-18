import hashlib
import struct

def pad_msg(bytemsg, msg_len):
    padded_msg = bytemsg + b'\x80'
    while (len(padded_msg) * 8) % 512 != 448:
        padded_msg += b'\x00'

    return padded_msg + bytes.fromhex(hex(msg_len)[2:].zfill(16))

def leftrotate(val, shift):
    return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

def sha1(bytemsg, msg_len=0, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):

    bytemsg = pad_msg(bytemsg, msg_len)
    msg_blocks = [ bytemsg[i:(i+64)] for i in range(0, len(bytemsg), 64) ]

    for block in msg_blocks:

        w = [0] * 80
        for i in range(16):
            w[i] = struct.unpack('>I', block[i*4:(i*4+4)])[0]

        for i in range(16, 80):
            w[i] = leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            f = d ^ (b & (c ^ d))                       # using alternative since original algorithm "requires" 2**32 modulo
            k = 0x5A827999
            if 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e, d, c, b, a = d, c, leftrotate(b, 30), a, temp

        h0, h1, h2, h3, h4 = (h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF, (h2+c) & 0xFFFFFFFF, (h3+d) & 0xFFFFFFFF, (h4+e) & 0xFFFFFFFF

    return hex(h0 << 128 | h1 << 96 | h2 << 64 | h3 << 32 | h4)


if __name__ == '__main__':

    import random
    msg = b'A' * random.randrange(0, 100)
    output = sha1(msg, len(msg)*8)

    model = hashlib.sha1()
    model.update(msg)

    assert output[2:].zfill(40) == model.hexdigest(), f"output hash {output[2:].zfill(40)} and model hash {model.hexdigest()} for message {msg}"
