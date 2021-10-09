import random
import requests
import hashlib
from set5.chall_one import modexp
from set4.sha1 import sha1
from set2.chall_two import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
from set2.chall_seven import pkcs7_unpad

g = 2
k = 3
N = 0xAE337C2E7228123DD88CD6474CEAAD38E513DA59706B3302AF294A524C948A9A609A6BE6A7D83EFAB3045281A42D808DF454E3AC54357FEED510D45F99AFF6D6F1FDC8B8B45614A80BE3E02706778C69549FEC41D71EDC729BB578BE7D36321664533162207A366E24B60F99D4B6C42F61986D05DE1BF9D4C8E9B57BC04DA7872D1A6EF45D0907DC572D4CF1E923176D1BC79A49012A17F4E5DF4A9E62B8A7FCD108641A7AE9BC4848CB3050564F2865F2A756FDC4F99FCF895176BB73D6E27DB3C7870A3C0536F34017C290BC6EF68343B8D141BBF2F036050871D55E282FD99B27C9A400D9CE47F31ADD3DF50232BB2BA065D9329AABD7B1793C540B99E9B7
creds = { 'lucas@ljhsiung.com' : 'p@ssw0rd' }

def main():
    a = random.randint(0, N)
    A = modexp(g, a, N)
    payload = { 'email': 'lucas@ljhsiung.com',
                'pubKey': A}
    r = requests.post("http://localhost:9000/login", json=payload)
    respJson = r.json()
    salt, B = respJson['salt'], respJson['serverKey']

    uH = hashlib.sha256((hex(A)[2:]+B).encode()).hexdigest()
    u = int(uH, 16)

    xH = hashlib.sha256(salt.encode() + 'p@ssw0rd'.encode()).hexdigest()
    x = int(xH, 16)
    S = modexp((int(B, 16) - k*modexp(g,x,N)), a + u*x, N)
    K = hashlib.sha256(hex(S)[2:].encode()).hexdigest()

    hmac_sha2 = hashlib.pbkdf2_hmac('sha256', K.encode(), salt.encode(), 100000).hex()
    r = requests.post("http://localhost:9000/validate", json={'hmac' : hmac_sha2})

    print(r.text)
    assert r.ok
    print("Server accepted credentials")


if __name__ == '__main__':
    main()
