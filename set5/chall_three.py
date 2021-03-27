import random
import binascii
from set5.chall_one import modexp
from set4.sha1 import sha1
from set2.chall_two import cbc_encrypt, cbc_decrypt
from set2.chall_three import get_random_int
from set2.chall_seven import pkcs7_unpad


def mallory_decrypt(alice_encrypt, bob_encrypt, g, p, S):
    bytes_S = hex(S)[2:].encode()
    sha_S = sha1(bytes_S,len(bytes_S)*8)
    shared_S = sha_S[2:][:32]
    iv_b = alice_encrypt[-32:]
    alice_ciphertext = alice_encrypt[:-32]
    bob_decrypt = cbc_decrypt(alice_ciphertext, shared_S, iv_b)
    padding = int(bob_decrypt[-1], 16)*2
    bob_decrypt = bob_decrypt[:-padding]

    return binascii.unhexlify(bob_decrypt)

def chall_two_phase_1(p, g):

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

    return alice_encrypt, bob_encrypt


def main():
    # Chall 2 original phase 1
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    alice_encrypt, bob_encrypt = chall_two_phase_1(p, g)

    print("\n---------------------------------")
    print("ATTACK FOR G = 1")
    print("---------------------------------\n")
    g = 1
    alice_encrypt, bob_encrypt = chall_two_phase_1(p, g)
    # S == 1^a^b mod p == 1
    S = 1
    decrypt_S1 = mallory_decrypt(alice_encrypt, bob_encrypt, g, p, S)

    print("\n---------------------------------")
    print("ATTACK FOR G = P")
    print("---------------------------------\n")
    g = p
    alice_encrypt, bob_encrypt = chall_two_phase_1(p, g)
    # S == p^a^b mod p == (p mod p)*(p mod p)*... == 0
    S = 0
    decrypt_S2 = mallory_decrypt(alice_encrypt, bob_encrypt, g, p, S)

    print("\n---------------------------------")
    print("ATTACK FOR G = P - 1")
    print("---------------------------------\n")
    g = p - 1
    chall_two_phase_1(p, g)
    alice_encrypt, bob_encrypt = chall_two_phase_1(p, g)
    # S == (p-1)^a^b mod p           == (p-1 mod p)*(p-1 mod p)*...
    #   == (-1 mod p)*(-1 mod p)*...
    #   == -1^(a*b)
    # Thus, S == 1 or -1 == p - 1
    print("################################\n")
    print("Trying for S = 1\n")
    S = 1
    decrypt_S3_0 = mallory_decrypt(alice_encrypt, bob_encrypt, g, p, S)
    # Try again for S = P - 1
    print("################################\n")
    print("Trying for S = P - 1\n")
    S = p - 1
    decrypt_S3_1 = mallory_decrypt(alice_encrypt, bob_encrypt, g, p, S)
    # if A == B == p, keys are just 0 since p^k mod p == 0

    #A, B = modexp(g,a,p), modexp(g,b,p)

    #M_A, M_B = p, p

    #S = modexp(M_A,b,p)
    #bytes_S = hex(S)[2:].encode()
    #print(f"shared secret is: {S}")
    #assert S == modexp(M_B,a,p)

    #sha_S = sha1(bytes_S,len(bytes_S)*8)
    #print(f"shared secret is: {S}")
    #shared_S = sha_S[2:][:32]
    print(f"Decrypted message for first key (0) is: \t {decrypt_S1}")
    print(f"Decrypted message for second key (1) is: \t {decrypt_S2}")
    print(f"Decrypted message for third key (1) is: \t {decrypt_S3_0}")
    print(f"Decrypted message for third key (p-1) is: \t {decrypt_S3_1}")


if __name__ == '__main__':
    main()
