import codecs

def hex_to_base64(hex_str):
    return codecs.encode( codecs.decode(hex_str, 'hex'), 'base64').decode()

