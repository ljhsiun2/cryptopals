from set1.chall_two import xor_hex_strings
import codecs
import binascii

# http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
# https://reusablesec.blogspot.com/2009/05/character-frequency-analysis-info.html
# added some custom "acceptable" english characters still, like spaces or exclamation marks
englishLetterFreq = {'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07, ' ': 13, '\\': 0, '\'': 2, '.': 1, ',': 1, '-': 0, "!": 0, "\"": 2, "?": 1, ":": 0, "/": 0}


# counts number ASCII bytes in hex string
def score_string(hex_str):
    score = 0.0
    for c in hex_str:
        score += englishLetterFreq.get(chr(c).upper(), -100)
    return score

def xor_single_byte(hex_str):
    best_score = -1000
    best_string = ''
    key_byte = 0
    for i in range(0, 256):
        decrypted = xor_hex_strings(hex_str, (int(len(hex_str)/2)*bytes([i])).hex() )
        if len(decrypted)%2: decrypted = '0' + decrypted
        temp_score = score_string(binascii.unhexlify(decrypted))

        if temp_score > best_score:
            best_score = temp_score
            best_string = codecs.decode(decrypted, 'hex')
            key_byte = i


    return (best_string, best_score, key_byte)

#test = xor_single_byte('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
#print(test)
