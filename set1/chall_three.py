import chall_two
import codecs
import binascii

englishLetterFreqUp = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07, ' ': 1}


englishLetterFreqLow = {'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07, ' ': 1}

# counts number ASCII bytes in hex string
def score_string(hex_str):
    score = 0.0
    for c in hex_str:
        if chr(c) in englishLetterFreqUp:
            score += englishLetterFreqUp[chr(c)]
        elif chr(c) in englishLetterFreqLow:
            score += englishLetterFreqLow[chr(c)]
        else:
            score -= 10     # kinda assuming if it's not an alphanumeric character, it "loses" score
    return score

def xor_single_byte(hex_str):
    best_score = 0
    best_string = ''
    key_byte = 0
    for i in range(0, 256):
        decrypted = chall_two.xor_hex_strings(hex_str, int(len(hex_str)/2)*bytes([i]).hex() )
        format_decrypted = '0' * (len(decrypted)%2) + decrypted[2:]
        temp_score = score_string(binascii.unhexlify(format_decrypted))

        if temp_score > best_score:
            best_score = temp_score
            best_string = codecs.decode(format_decrypted, 'hex')
            key_byte = i

    return (best_string, best_score, key_byte)

#test = xor_single_byte('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
#print(test)
