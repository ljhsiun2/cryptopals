from set3.chall_six import *
from set3.chall_five import *

def undo_right_shift(rng_val, shift_val):

    # y_i = y_{i-1} ^ (y_{i-1} >> L)
    # NOTE: first "temper" has a mask of 0xFFF..F, which doesn't matter if you right shift
    # we can derive the L (18) most significant bits from pure inspection
    # since y_{i-1} >> L simply zeroes out L (18) MSBs and anything ^ 0 is itself

    # furthermore, we can derive the remaining {bit_length - L} (i.e. 14) bits by
    # using the MSBs as our other XOR argument. Since we know (y_{i-1} >> L) and
    # y_i, we can easily solve for y_{i-1} by XOR-ing y_i with (y_{i-1} >> L).

    rng_bin = format(rng_val, '032b')
    y = rng_bin[:shift_val]
    y_prev = y

    for i in range(shift_val, w, shift_val):
        y_orig = rng_bin[i:(i+shift_val)]
        y_shift = y[(i-shift_val):i][:len(y_orig)]
        y_prev = int(y_orig, 2) ^ int(y_shift, 2)

        y += format(y_prev, f'0{min(w-i, shift_val)}b')

    return int(y, 2)

def undo_left_shift(rng_val, shift_val, and_val):
    # y_i = y_{i-1} ^ ( (y_{i-1} << shift_val) & and_val)
    # looking at the properties of the magic numbers and shifts ({t,c} and {s,b})
    # we can see the and_val has the lowest shift_val bits as 0s.
    # this tells us that the lowest bits of y_{i-1} are the same as y_i

    # to derive the MSBs, suppose for simplicity our shift_val and and_val
    # are T and C (15, 0xEFC60000)
    # With only the above knowledge, the value for (y_{i-1} << shift_val)
    # looks something like this:
    #   {2'bx, 15'b<known>, 15'b0}
    # and y_{i-1} so far looks something like this:
    #   {17'bx, 15'b<known>}
    # where 'x' is the unknown bits. This is systemverilog notation TODO explain notation
    # Note that bits 16 and 17 of y_{i-1} are the same as bits 32 and 31 of y_{i-1} shifted.

    # We can further derive the "middle" 15 bits ([29:15]) since we know the shifted y value
    # and therefore, also know bits 16 and 17 and thus the rest of the shifted y value.

    # This can be recognizing that at every step, we could derive shift_val bits of y_{i-1} at a time
    # (up to the width w), which in turn reveals more information about y_shift, which in turn reveals
    # more about y_{i-1}. It's a positive feedback loop :)

    rng_bin = format(rng_val, '032b')
    and_bin = format(and_val, '032b')
    y = rng_bin[-shift_val:]
    y_prev = int(y, 2)

    for i in range(shift_val, w, shift_val):
        y_shift = y_prev
        and_bits = int(and_bin[-(i+shift_val):-i], 2)
        y_origin = int(rng_bin[-(i+shift_val):-i], 2)

        y_prev = y_origin ^ (y_shift & and_bits)

        y = format(y_prev, f'0{shift_val}b') + y

    return int(y, 2)


def main():
    for i in range(10):
        seed_mt(i)
        for index in range(624):
            num = extract_number()

            pre_L_shift_num = undo_right_shift(num, l)
            pre_T_shift_num = undo_left_shift(pre_L_shift_num, t, c)
            pre_S_shift_num = undo_left_shift(pre_T_shift_num, s, b)
            rng_state =       undo_right_shift(pre_S_shift_num, u)

            # Check computed state == mt state
            mt_state = get_mt()
            assert mt_state[index] == rng_state


    print("Successfully dumped all MT19937 state")

if __name__ == '__main__':
    main()
