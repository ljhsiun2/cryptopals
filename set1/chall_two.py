import codecs

def hex_to_base64(hex_str):
    return codecs.encode( codecs.decode(hex_str, 'hex'), 'base64').decode()

def xor_hex_strings(hex_str_one, hex_str_two):

    assert(len(hex_str_one) == len(hex_str_two))
    ret_str = hex(int(hex_str_one, 16) ^ int(hex_str_two, 16) )[2:]
    if len(ret_str) != len(hex_str_one): ret_str = '0' + ret_str
    return ret_str

#print(xor_hex_strings('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))
#assert('746865206b696420646f6e277420706c6179' == xor_hex_strings('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965'))
#
