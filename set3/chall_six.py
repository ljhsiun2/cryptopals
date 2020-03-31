from random import randint
from time import time
from set3.chall_five import *

def wait_rng():
    # gets rng and waits as spec in challenge
    current_time = int(time())
    current_time += randint(40, 1000)
    seed_mt(current_time)
    print(f"RNG time is {current_time}")
    rng_num = extract_number()
    current_time += randint(40, 1000)

    return current_time, rng_num

def get_mt_seed(cur_time, rng_val):
    test_time, temp_rng = cur_time, 0
    while rng_val != temp_rng:
        seed_mt(test_time)
        temp_rng = extract_number()
        test_time -= 1

    return test_time + 1


def main():
    rng_time, rng = wait_rng()
    found_seed = get_mt_seed(rng_time, rng)
    print(f"found RNG seed time! {found_seed}")


if __name__ == '__main__':
    main()
