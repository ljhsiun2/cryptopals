from set4.chall_seven_client import get_next_byte
import requests

def main():

    hmac_guess = bytearray(b'\xff'*20)  # 20 == sha1 length of digest in bytes
    filename = "foo"

    for i in range(20):
        hmac_guess[i] = get_next_byte(filename, hmac_guess, i, 100)

    print(f"guessed hmac is {hmac_guess}")
    r = requests.get(f"http://localhost:9000/test?file={filename}&signature={hmac_guess.hex()}")

    assert r.status_code == 200, f"wrong hmac {hmac_guess.hex()}: is timing in server wrong (chall_seven_server.py)?"
    print(r.content, r.status_code)

    # you can even reduce the "sleep" to 0.00001 (10us) if you up the samples and have the patience
    # roughly translates to 10000 cpu cycles (for a 1ghz cpu) which is *slightly*
    # more realistic (maybe could be caused by a particularly bad page fault)
    # for i in range(20):
    #     hmac_guess[i] = get_next_byte(filename, hmac_guess, i, 100)

    # print(f"guessed hmac is {hmac_guess}")
    # r = requests.get(f"http://localhost:9000/test?file={filename}&signature={hmac_guess.hex()}")

    # assert r.status_code == 200, f"wrong hmac {hmac_guess.hex()}: is timing in server wrong (chall_seven_server.py)?"
    # print(r.content, r.status_code)

if __name__ == '__main__':
    main()
