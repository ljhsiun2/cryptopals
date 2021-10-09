import random
import requests
import hashlib
from set5.chall_one import modexp

g = 2
k = 3
N = 0xAE337C2E7228123DD88CD6474CEAAD38E513DA59706B3302AF294A524C948A9A609A6BE6A7D83EFAB3045281A42D808DF454E3AC54357FEED510D45F99AFF6D6F1FDC8B8B45614A80BE3E02706778C69549FEC41D71EDC729BB578BE7D36321664533162207A366E24B60F99D4B6C42F61986D05DE1BF9D4C8E9B57BC04DA7872D1A6EF45D0907DC572D4CF1E923176D1BC79A49012A17F4E5DF4A9E62B8A7FCD108641A7AE9BC4848CB3050564F2865F2A756FDC4F99FCF895176BB73D6E27DB3C7870A3C0536F34017C290BC6EF68343B8D141BBF2F036050871D55E282FD99B27C9A400D9CE47F31ADD3DF50232BB2BA065D9329AABD7B1793C540B99E9B7
creds = { 'user': 'lucas@ljhsiung.com',
          'pass': 'Passw0rd' }

def send_pubKey(pubKey):
    r = requests.post("http://localhost:9000/chall_six", json={'pubKey' : pubKey})
    respJson = r.json()

    salt, serverKey, challenge = respJson['salt'], respJson['serverKey'], respJson['challenge']
    return salt, serverKey, challenge

def validate(hmac):
    r = requests.post("http://localhost:9000/chall_six_validate", json={'hmac_token' : hmac})

    return r.ok

def phase_one():
    a = random.randint(0, N)
    A = modexp(g, a, N)

    salt, server_pubKey, challenge = send_pubKey(A)

    xH = hashlib.sha256(salt.encode() + creds['pass'].encode())
    x = int(xH.hexdigest(), 16)

    shared_S = modexp(server_pubKey, a + x*challenge, N)
    K = hashlib.sha256(hex(shared_S).encode()).hexdigest()

    hmac = hashlib.pbkdf2_hmac('sha256', K.encode(), salt.encode(), 100000).hex()

    retCode = validate(hmac)

    print(f"-\thmac: {hmac} ret code {retCode}")



def main():

    print("PHASE ONE: Setting up honest server")
    r = requests.get("http://localhost:9000/chall_six_honest_server")
    assert r.ok
    phase_one()


    print("PHASE TWO: Setting up malicious server")
    r = requests.get("http://localhost:9000/chall_six_mal_server")
    assert r.ok
    phase_one()


if __name__ == '__main__':
    main()
