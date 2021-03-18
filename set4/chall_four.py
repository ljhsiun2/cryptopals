from set4.sha1 import sha1

def sha1_mac(key, msg):
    return sha1(key + msg, len(key+msg)*8)[2:].zfill(40)

if __name__ == '__main__':

    import random
    import hashlib

    key = b'YELLOW SUBMARINE'
    msg = b"A"*random.randrange(0, 1000)

    assert sha1_mac(key, msg) == hashlib.sha1(key+msg).hexdigest(), f"our mac: {sha1_mac(key, msg)} model mac: {hashlib.sha1(key+msg).hexdigest()}"
