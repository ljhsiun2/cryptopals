import base64
from set1.chall_two import xor_hex_strings
from set1.chall_three import xor_single_byte
from set1.chall_five import xor_encrypt_string

def hamming_distance(str1, str2):
    assert(len(str1) == len(str2))
    hex_str1 = str1.hex()
    hex_str2 = str2.hex()
    # can find hamming distance by just xoring and counting number of 1s in xord result
    xor_strings = xor_hex_strings(hex_str1, hex_str2)
    num_ones = sum([1 for c in bin(int(xor_strings, 16))[2:] if c == '1'])

    return num_ones

def find_likely_keysize(message, lower, upper):
    keysize = 0
    keysz_scores = {}
    for i in range(lower, upper+1):
        block_array = []

        block_array = [message[j*i:(j+1)*i] for j in range(0, len(message), i) if len(message[j*i:(j+1)*i]) == i]

        total = [ hamming_distance(block_array[c], block_array[c+1])/i for c in range(0, len(block_array)-1) ]
        keysz_scores[i] = sum(total)/len(total)

    return keysz_scores

def partition_block(message, partition):
    return [ message[partition*i:partition*(i+1)] for i in range(0, partition) ]

def transpose_blocks(message, key_sz):
    transposed_blocks = []
    partitioned_blocks = partition_block(message, key_sz)
    for byte_i in range(0, key_sz):
        transposed_block_i = ''
        transposed_block_i = ''.join([ chr(block[byte_i]) for block in partitioned_blocks ])
        transposed_blocks.append(transposed_block_i)

    return transposed_blocks

def decrypt_message(message, key):
    partitioned_blocks = partition_block(message, len(key))
    #print(partitioned_blocks)
    return ''.join([  ''.join([ chr( ord(key[i]) ^ block[i] ) for i in range(0, len(key) ) ]) for block in partitioned_blocks ])

def main():
    with open('6.txt', 'r') as f:

        #print( base64.b64decode(f.read()))
        message = base64.b64decode(f.read().strip())

        keysize_dict = find_likely_keysize(message, 2, 40)
        sorted_scores = sorted(keysize_dict.values())

        # get top 4 scores; cryptopals recommends 3, but go the extra mile!
        best_scores = ( sorted_scores[0], sorted_scores[1], sorted_scores[2], sorted_scores[3] )
        best_key_len = [ key for key in keysize_dict if keysize_dict[key] in best_scores ]
        best_key_scores = set(zip(best_key_len, best_scores))

        potential_keys = []
        for key_sz, score in best_key_scores:
            transposed_blocks = transpose_blocks(message, key_sz)

            #print(f"\n------\nUsing KEYSIZE = {key_sz}\n------")
            probable_key = ''
            for block in transposed_blocks:
                #print( xor_single_byte(block.encode()) )
                (decrypted_str, score, key_byte) = xor_single_byte(block.encode().hex())
                if score != 0:
                   probable_key += chr(key_byte)

            if key_sz == len(probable_key):
                potential_keys.append(probable_key)

        print(f"\nProbable key is \"{potential_keys}\"\n\n")

        dec_message = decrypt_message(message, potential_keys[0])
        print(dec_message)
    #Probable key is "['Terminator X: Bring the noise']"

if __name__ == '__main__':
    main()
