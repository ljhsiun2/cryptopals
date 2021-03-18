import random
from set5.chall_one import modexp
from set4.sha1 import sha1
from set2.chall_two import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
from set2.chall_seven import pkcs7_unpad

def main():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2

    # Alice and Bob generate private keys
    a, b = random.randint(0, p), random.randint(0, p)

    # Alice and Bob sends public messages
    A, B = modexp(g,a,p), modexp(g,b,p)

    print(f"These are public info! \np: \t\t\t{hex(p)} \ng: {g}\nAlice public key: \t{hex(A)}\nBob public key: \t{hex(B)}")

    # Now, generate shared secret S by computing
    # S == A^b == B^a
    S = modexp(A,b,p)
    bytes_S = hex(S)[2:].encode()
    assert S == modexp(B,a,p), "Shared secret miscomputed"

    # 1a) Preparing to send Bob the message

    iv_a = get_random_int(128)
    sha_S = sha1(bytes_S,len(bytes_S)*8)
    print(f"shared secret is: {S}")
    shared_S = sha_S[2:][:32]

    alice_msg = "This is the password. Pass it on!".encode().hex()
    alice_encrypt = cbc_encrypt(alice_msg, shared_S, iv_a) + iv_a
    print(f"Here is my (alice's) encrypted text: \t\t{alice_encrypt}")

    print("\n~~~~~SENDING MESSAGE~~~~~~ PLS NO INTERCEPT ~~~~~")
    print("~~~~~BUT EVEN IF YOU DO THIS IS UNHAXABLE~~~~~~~~\n")

    # 1b) Bob receives the message
    #     Confirming that Bob received the message from Alice correctly
    iv_b = alice_encrypt[-32:]
    alice_ciphertext = alice_encrypt[:-32]
    bob_decrypt = cbc_decrypt(alice_ciphertext, shared_S, iv_b)
    padding = int(bob_decrypt[-1], 16)*2
    bob_decrypt = bob_decrypt[:-padding]

    assert bob_decrypt == alice_msg

    iv_b = get_random_int(128)
    bob_encrypt = cbc_encrypt(bob_decrypt, shared_S, iv_b) + iv_b
    print(f"Thanks! Here is my (bob's) encrypted text: \t{bob_encrypt}")

    # 2) Bob sending message back to Alice

    iv_b = bob_encrypt[-32:]
    bob_ciphertext = bob_encrypt[:-32]
    alice_decrypt = cbc_decrypt(bob_ciphertext, shared_S, iv_b)
    padding = int(alice_decrypt[-1], 16)*2
    alice_decrypt = alice_decrypt[:-padding]

    assert alice_decrypt == alice_msg

    """
    PHASE 2
    """
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print(" PHASE 2 ")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~")

    # if A == B == p, keys are just 0 since p^k mod p == 0

    A, B = modexp(g,a,p), modexp(g,b,p)

    M_A, M_B = p, p

    S = modexp(M_A,b,p)
    bytes_S = hex(S)[2:].encode()
    print(f"shared secret is: {S}")
    assert S == modexp(M_B,a,p)

    sha_S = sha1(bytes_S,len(bytes_S)*8)
    print(f"shared secret is: {S}")
    shared_S = sha_S[2:][:32]

    """
    Because the shared secret is 0, we can trivially figure out
    the resulting hash (sha1(NULL)). We can also derive the IV
    since it's just padded at the end of the message,
    and we also have posession of the message's ciphertext.

    Personally, I don't see much reason to redo the experiment :)
    """


if __name__ == '__main__':
    main()
