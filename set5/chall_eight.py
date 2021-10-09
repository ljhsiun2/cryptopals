from sympy import integer_nthroot
from set5.chall_seven import rsa_encrypt, rsa_decrypt, get_rsa_keys, mod_inv
import codecs


def main():

    # Try changing e=3, and you'll see that a larger number won't work
    message = "hello world!".encode().hex()
    js_e0, js_d0, js_n0 = get_rsa_keys(512, e=3)
    js_e1, js_d1, js_n1 = get_rsa_keys(512, e=3)
    js_e2, js_d2, js_n2 = get_rsa_keys(512, e=3)

    ct0 = rsa_encrypt(js_e0, message, js_n0)
    assert message == rsa_decrypt(js_d0, ct0, js_n0)
    ct1 = rsa_encrypt(js_e1, message, js_n1)
    assert message == rsa_decrypt(js_d1, ct1, js_n1)
    ct2 = rsa_encrypt(js_e2, message, js_n2)
    assert message == rsa_decrypt(js_d2, ct2, js_n2)

    n_01 = js_n0 * js_n1
    n_12 = js_n1 * js_n2
    n_02 = js_n0 * js_n2
    n_012 = n_01 * js_n2

    ct0_int, ct1_int, ct2_int = int(ct0, 16), int(ct1, 16), int(ct2, 16)

    # https://www.di-mgt.com.au/crt.html#gaussalg
    result = ct0_int * n_12 * mod_inv(n_12, js_n0)\
            +ct1_int * n_02 * mod_inv(n_02, js_n1)\
            +ct2_int * n_01 * mod_inv(n_01, js_n2)
    result %= n_012

    decrypt = integer_nthroot(result, 3)
    decrypt = decrypt[0]
    ascii_msg = codecs.decode(hex(decrypt)[2:], "hex")
    print(f"decrypted message! {ascii_msg}")
    assert message == hex(decrypt)[2:]


if __name__ == "__main__":
    main()
