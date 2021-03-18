import random

# compute a^b mod c
def modexp(a, b, c):
    res = 1

    # just simple exponentiation by squaring
    while(b > 0):
        if (b & 1):
            res = (res * a) % c

        b >>= 1
        a = (a*a) % c

    return res

def main():
    p, g = 37, 5

    a, b = random.randint(0, p), random.randint(0, p)
    A, B = (g ** a) % p, (g**b) % p

    s = (B ** a) % p
    s_ = (A ** b) % p
    assert s == s_, "failed public key verification"

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a, b = random.randint(0, p), random.randint(0, p)
    A, B = modexp(g,a,p), modexp(g,b,p)
    s, s_ = modexp(B,a,p), modexp(A,b,p)

    assert s == s_, "failed public key verification step 2"


if __name__ == '__main__':
    main()
