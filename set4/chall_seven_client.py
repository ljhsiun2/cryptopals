import requests

def get_next_byte(filename, cur_bytes, byte_num, num_samples=1):

    def sort(a):
        return a[1]

    response_times = []
    best_time = 0
    for i in range(256):
        cur_bytes[byte_num] = i
        attempts = []
        for _ in range(num_samples):
            r = requests.get(f"http://localhost:9000/test?file={filename}&signature={cur_bytes.hex()}")
            attempts.append(r.elapsed.total_seconds())
        avg_times = sum(attempts)/num_samples
        response_times.append((i, avg_times))

    response_times.sort(key=sort)
    print(response_times)
    guessed_byte = response_times.pop()[0]
    print(f"guessed byte is {hex(guessed_byte)}")
    return guessed_byte


def main():

    hmac_guess = bytearray(b'\xff'*20)  # 20 == sha1 length of digest in bytes
    filename = "foo"

    for i in range(20):
        hmac_guess[i] = get_next_byte(filename, hmac_guess, i)
    # cbd719c2ca579c2740a28eb257dcc1ab68e4b85e

    print(f"guessed hmac is {hmac_guess}")
    r = requests.get(f"http://localhost:9000/test?file={filename}&signature={hmac_guess.hex()}")
    assert r.status_code == 200, f"wrong hmac {hmac_guess.hex()}: is timing in server wrong (chall_seven_server.py)?"
    print(r.content, r.status_code)

if __name__ == '__main__':
    main()
