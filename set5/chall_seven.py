from sympy import randprime, isprime
from set5.chall_one import modexp

def mod_inv(a, n):
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
    t, r, temp_T, temp_R = 0, n, 1, a

    while temp_R != 0:
        quotient = r // temp_R
        t, temp_T = temp_T, t - (quotient * temp_T)
        r, temp_R = temp_R, r - (quotient * temp_R)

    if t < 0:
        t += n

    return t

def rsa_encrypt(key, plaintext, n):
    pt_int = int(plaintext, 16)
    ct_int = rsa_encrypt_int(key, pt_int, n)
    return hex(ct_int)[2:]

def rsa_encrypt_int(key, plaintext, n):
    return modexp(plaintext, key, n)

def rsa_decrypt(key, ciphertext, n):
    ct_int = int(ciphertext, 16)
    pt_int = rsa_decrypt_int(key, ct_int, n)
    return hex(pt_int)[2:]

def rsa_decrypt_int(key, ciphertext, n):
    return modexp(ciphertext, key, n)

def get_rsa_keys(keysize=16, e=3):
    d, n = 1, 0
    while d == 1:
        p, q = randprime(2**(keysize-1), 2**keysize), randprime(2**(keysize-1), 2**keysize)
        n = p * q
        et = (p-1)*(q-1)
        d = mod_inv(e, et)

        if d == 1:
            print(f"mod inv for {e}, {hex(n)} doesn't exist, retrying")

    return e, d, n


def main():
    res = mod_inv(7, 26)
    assert 15 == res

    res = mod_inv(3, 11)
    assert 4 == res

    res = mod_inv(10, 17)
    assert 12 == res

    assert mod_inv(17, 3120) == 2753

    e, d, n = get_rsa_keys()
    pubKey = (e, n)
    privKey = (d, n)

    # https://tls.mbed.org/kb/cryptography/rsa-encryption-maximum-data-size
    message = 42
    ct = rsa_encrypt_int(pubKey[0], message, n)
    pt = rsa_decrypt_int(privKey[0], ct, n)
    assert message == pt, "message != decrypt(encrypt(message))"

    e, d, n = get_rsa_keys(64)
    pubKey = (e, n)
    privKey = (d, n)

    message = "hi".encode().hex()
    ct = rsa_encrypt(pubKey[0], message, n)
    pt = rsa_decrypt(privKey[0], ct, n)
    assert message == pt, "message != decrypt(encrypt(message))"


if __name__ == "__main__":
    main()
