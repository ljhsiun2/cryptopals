from flask import Flask, request
import time
from set4.sha1 import sha1
from set1.chall_two import xor_hex_strings

app = Flask(__name__)

sleep_time = 0.000001
key = b"password LUL"

def hmac_sha1(key, msg):

    assert type(msg) == bytes
    assert type(key) == bytes

    if len(key) > 64:
        key = sha1(key, len(key)*8)
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))

    o_key_pad = bytes.fromhex(xor_hex_strings(key.hex(), (b'\x5c'*64).hex()))
    i_key_pad = bytes.fromhex(xor_hex_strings(key.hex(), (b'\x36'*64).hex()))

    i_pad_hash = bytes.fromhex(sha1(i_key_pad + msg, len(i_key_pad + msg)*8)[2:])

    return sha1(o_key_pad + i_pad_hash, len(o_key_pad + i_pad_hash)*8)[2:]

def insecure_compare(str1, str2):
    for a, b in zip(str1, str2):
        if a != b:
            return 0
        time.sleep(sleep_time)
    return 1


@app.route('/test', methods=['GET'])
def verify_file():

    if request.method == 'GET':
        parameters = request.query_string.decode().split('&')
        req_file, req_hmac = parameters[0].split('=')[1], parameters[1].split('=')[1]

        computed_hmac = hmac_sha1(key, req_file.encode())
        if insecure_compare(computed_hmac, req_hmac):
            return "verification success!", 200
        else:
            return "you suck stop hacking", 500
    else:
        return "Unsupported method"

if __name__ == "__main__":
    app.run(port=9000)
