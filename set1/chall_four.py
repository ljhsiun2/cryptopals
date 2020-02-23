from chall_three import xor_single_byte

def decrypt_file(filename):
    with open(filename, 'r') as f:
        score = 0
        best_decrypt_string = ''
        best_key = 0
        for line in f:
            (decrypt, temp_score, key) = xor_single_byte(line.strip())
            if temp_score > score:
                score = temp_score
                best_decrypt_string = decrypt
                best_key = key

        return (best_decrypt_string, score, best_key)

#print(decrypt_file('4.txt'))
