import hashlib
import json
import random
from flask import Flask, request
from set2.chall_three import get_random_int
from set5.chall_one import modexp
from threading import Thread


g = 2
k = 3
N = 0xAE337C2E7228123DD88CD6474CEAAD38E513DA59706B3302AF294A524C948A9A609A6BE6A7D83EFAB3045281A42D808DF454E3AC54357FEED510D45F99AFF6D6F1FDC8B8B45614A80BE3E02706778C69549FEC41D71EDC729BB578BE7D36321664533162207A366E24B60F99D4B6C42F61986D05DE1BF9D4C8E9B57BC04DA7872D1A6EF45D0907DC572D4CF1E923176D1BC79A49012A17F4E5DF4A9E62B8A7FCD108641A7AE9BC4848CB3050564F2865F2A756FDC4F99FCF895176BB73D6E27DB3C7870A3C0536F34017C290BC6EF68343B8D141BBF2F036050871D55E282FD99B27C9A400D9CE47F31ADD3DF50232BB2BA065D9329AABD7B1793C540B99E9B7
creds = { 'user' : 'lucas@ljhsiung.com',
          'pass' : 'Passw0rd' }

app = Flask(__name__)

class MalData():
    # Data received for a MITM attacker
    def __init__(self):
        self.I = 0
        self.A = 0
        self.salt = 0
        self.b = 0
        self.B = 0
        self.u = 0
        self.hmac = 0
        self.enabled = 0

class Database():
    b = 0
    salt = 0
    v = 0
    u = 0
    uH = ''

    serverKey = 0
    # Computed S, K
    S = 0
    K = ''

# globals
DB = Database()
MitmAttacker = MalData()

def crack():
    # We know the protocol being run, so we can recompute every step
    # and compare against the MITM information
    # Further, since we're a malicious server, we can just forge a lot of stuff
    # e.g. b, B, u, salt
    # key compute steps are:
    #   - x = SHA256(salt + pass)   // WE KNOW SALT; WILL GUESS PASS
    #   - ((A * (v ** u)) ** b) % N // WE KNOW b and u
        # ((A * (v ** u)) ** b) % N
    with open("/usr/share/dict/xato-net-10-million-passwords-100000.txt", "r") as passFile:
        print("==================")
        print("RUNNING OFFLINE ATTACK")
        print("==================")

        for password in passFile:
            xH = hashlib.sha256(MitmAttacker.salt.encode() + password.strip().encode())
            x = int(xH.hexdigest(), 16)
            v = modexp(g, x, N)

            temp_base = MitmAttacker.A * modexp(v, MitmAttacker.u, N)
            S = hex(modexp(temp_base, MitmAttacker.b, N))
            K = hashlib.sha256(S.encode()).hexdigest()
            computed_hmac = hashlib.pbkdf2_hmac('sha256', K.encode(), MitmAttacker.salt.encode(), 100000).hex()

            captured_hmac = MitmAttacker.hmac

            print(f"comparing password {password.strip()}: {computed_hmac} against {captured_hmac}")

            if computed_hmac == captured_hmac:
                print(f"HACKED PASSWORD: {password}")
                return

        print("did not find password in dictionary; try again!")



@app.route('/chall_six', methods=['POST'])
def chall_six():

    if request.method == "POST":
        payload = request.get_json()
        client_pubKey = payload['pubKey']
        serverKey = DB.serverKey

        respData = json.dumps({"salt": DB.salt,"serverKey": serverKey, "challenge":DB.u})

        # ((A * (v ** u)) ** b) % N
        temp_base = client_pubKey * modexp(DB.v, DB.u, N)
        DB.S = hex(modexp(temp_base, DB.b, N))
        DB.K = hashlib.sha256(DB.S.encode()).hexdigest()

        if MitmAttacker.enabled:
            MitmAttacker.A = client_pubKey

        return respData, 200

@app.route('/chall_six_validate', methods=['POST'])
def validate():

    server_hmac = hashlib.pbkdf2_hmac('sha256', DB.K.encode(), DB.salt.encode(), 100000).hex()

    print(server_hmac)

    if request.method == "POST":
        payload = request.get_json()
        client_hmac = payload['hmac_token']

        # hacky-- but we copy/capture all our information "online", and crack it after
        if MitmAttacker.enabled:
            MitmAttacker.hmac = client_hmac
            MitmAttacker.salt = DB.salt
            MitmAttacker.b = DB.b
            MitmAttacker.B = DB.serverKey
            MitmAttacker.u = DB.u
            thread = Thread(target=crack)
            thread.start()


        if server_hmac == client_hmac:
            return "OK", 200
        else:
            return "Validation Fail", 403

@app.route('/chall_six_honest_server', methods=['GET'])
def honest_server():
    salt = get_random_int(32)
    xH = hashlib.sha256(salt.encode() + creds['pass'].encode())
    x = int(xH.hexdigest(), 16)


    DB.v = modexp(g, x, N)

    # DB server state
    DB.salt = salt
    DB.b = random.randint(0, N)
    DB.serverKey = modexp(g, DB.b, N)
    DB.u = int(get_random_int(128),16)

    return "OK", 200

@app.route('/chall_six_mal_server', methods=['GET'])
def malicious_server():
    MitmAttacker.enabled = 1
    salt = get_random_int(32)
    xH = hashlib.sha256(salt.encode() + creds['pass'].encode())
    x = int(xH.hexdigest(), 16)


    DB.v = modexp(g, x, N)

    # DB server state
    DB.salt = salt
    DB.b = random.randint(0, N)
    DB.serverKey = modexp(g, DB.b, N)
    DB.u = int(get_random_int(128),16)

    return "OK", 200



def main():

    # PHASE 1

    app.run(port=9000)


if __name__ == '__main__':
    main()

#wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-100000.txt
#/usr/share/dict/xato-net-10-million-passwords-100000.txt

