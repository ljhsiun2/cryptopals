import random
import json
import hashlib
from flask import Flask, request
from set5.chall_one import modexp
from set2.chall_two import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
from set2.chall_seven import pkcs7_unpad

g = 2
k = 3
N = 0xAE337C2E7228123DD88CD6474CEAAD38E513DA59706B3302AF294A524C948A9A609A6BE6A7D83EFAB3045281A42D808DF454E3AC54357FEED510D45F99AFF6D6F1FDC8B8B45614A80BE3E02706778C69549FEC41D71EDC729BB578BE7D36321664533162207A366E24B60F99D4B6C42F61986D05DE1BF9D4C8E9B57BC04DA7872D1A6EF45D0907DC572D4CF1E923176D1BC79A49012A17F4E5DF4A9E62B8A7FCD108641A7AE9BC4848CB3050564F2865F2A756FDC4F99FCF895176BB73D6E27DB3C7870A3C0536F34017C290BC6EF68343B8D141BBF2F036050871D55E282FD99B27C9A400D9CE47F31ADD3DF50232BB2BA065D9329AABD7B1793C540B99E9B7

app = Flask(__name__)

class Database():
    b = 0
    salt = 0
    v = 0
    u = 0
    uH = ''

    # Computed S, K
    S = 0
    K = ''

DB = Database()

# Mutually shared/computed info
password = 'p@ssw0rd'
creds = { 'lucas@ljhsiung.com' : password }

# Client received info below
A = 0
email = ''

@app.route('/login', methods=['POST'])
def check_password():
    DB.b = random.randint(0, N)

    DB.salt = hex(random.randint(0, 2**32))[2:]
    xH = hashlib.sha256(DB.salt.encode() + password.encode()).hexdigest()
    x = int(xH, 16)
    DB.v = modexp(g, x, N)

    if request.method == "POST":
        payload = request.get_json()
        email, A = payload['email'], payload['pubKey']
        serverKey = hex(k*DB.v + modexp(g, DB.b, N))[2:]
        respData = json.dumps({"salt": DB.salt,"serverKey": serverKey})

        DB.uH = hashlib.sha256((hex(A)[2:]+serverKey).encode()).hexdigest()
        DB.u = int(DB.uH, 16)

        DB.S = modexp(A * modexp(DB.v, DB.u, N), DB.b, N)
        DB.K = hashlib.sha256(hex(DB.S)[2:].encode()).hexdigest()

        return respData, 200

@app.route('/validate', methods=['POST'])
def validate_K():

    if request.method == "POST":
        client_hmac = request.get_json()['hmac']

        server_hmac = hashlib.pbkdf2_hmac('sha256', DB.K.encode(), DB.salt.encode(), 100000).hex()

        if server_hmac == client_hmac:
            print("Validated credentials!")
            return "OK", 200
        else:
            print("Incorrect credentials STOOOP")
            return "FAIL", 500

def main():
    app.run(port=9000)

if __name__ == '__main__':
    main()
