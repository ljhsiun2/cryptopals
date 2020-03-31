python_MT = []
lmask = 0x7FFFFFFF
umask = 0x80000000

(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
index = n + 1
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
(l, f) = (18, 1812433253)

# functions for challenge seven
def set_mt(mt_state):
    global python_MT
    python_MT = mt_state

def get_mt():
    return python_MT

def seed_mt(seed):
    global index, python_MT
    assert type(seed) == int
    python_MT = []
    index = n
    python_MT.append(seed)
    for i in range(1, n):
        python_MT.append( ((1 << w) - 1) & (f * (python_MT[i-1] ^ (python_MT[i-1] >> (w-2)))) + i )

def twist():
    global index
    for i in range(n):
        x = (python_MT[i] & umask) + (python_MT[(i+1) % n] & lmask)
        x_A = x >> 1
        if x % 2 != 0:
            x_A ^= a
        python_MT[i] = python_MT[(i+m) % n] ^ x_A

    index = 0

def extract_number():
    global index
    if index >= n:
        if index > n:
            raise ValueError("Index exceeded state size")
        twist()

    y = python_MT[index]

    y ^= (y >> u) & d
    y ^= (y << s) & b
    y ^= (y << t) & c
    y ^= (y >> l)

    index += 1
    return ((1 << w) - 1) & y

def main():
    seed_mt(0)
    for _ in range(10):
        print(extract_number())

if __name__ == '__main__':
    main()
