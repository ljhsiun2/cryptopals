
def score(blocks):

    i = 0
    likely_text = ''
    likely_score = 100
    found_i = 0

    hexbytes = bytes.fromhex(blocks)
    blocks = [hexbytes[i:(i+16)].hex() for i in range(0, len(hexbytes), 16)]
    temp_score = len(set(blocks))
    if temp_score < likely_score:
        likely_score = temp_score
        likely_text = hexbytes.hex()
        found_line = i
    i += 1



with open('8.txt', 'r') as f:
    i = 0
    likely_text = ''
    likely_score = 100
    found_i = 0
    for line in f:
        hexbytes = bytes.fromhex(line.strip())
        blocks = [hexbytes[i:(i+16)].hex() for i in range(0, len(hexbytes), 16)]
        temp_score = len(set(blocks))
        if temp_score < likely_score:
            likely_score = temp_score
            likely_text = hexbytes.hex()
            found_line = i
        i += 1
    print(f"Found line {found_line} with score {likely_score}: text is {likely_text}")

