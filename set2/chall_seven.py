# expected input is Bytes type
def pkcs7_unpad(msg):
    padding = msg[-1]
    if padding == 0:
        raise ValueError("Cannot have 0 padding")
    #if len(msg) % 16 != 0:
    #    raise ValueError("Padded message not equal to block size")
    for c in range(len(msg) - padding, len(msg)-1):
        if msg[c] != padding:
            raise ValueError(f"Incorrect padding of message-- interpreted padding of {padding} but found {msg[c]} in message")
    return msg[:-padding]

#msg = ("ICE ICE BABY\x10" + "\x00"*15).encode()
#print(pkcs7_unpad(msg))
