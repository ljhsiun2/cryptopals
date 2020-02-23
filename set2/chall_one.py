def pkcs7_pad(msg, block_sz):
    msg = bytes.fromhex(msg)
    msg_blocks = [ msg[i:(i+block_sz)] for i in range(0, len(msg), block_sz) ]
    pad_len = block_sz - (len(msg) % block_sz)
    if len(msg_blocks[-1]) == block_sz: pad_len = block_sz
    return (msg + bytes([pad_len]*pad_len)).hex()


#msg = 'YELLOW SUBMARINEEEEEEEEE'
#msg = msg.encode().hex()
#pad = 20
#print(pkcs7_pad(msg, pad))
