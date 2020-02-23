# expected input is Bytes type
def pkcs7_unpad(msg):
    padding = msg[-1]
    for c in range(len(msg) - padding, len(msg)-1):
        if msg[c] != padding:
            raise ValueError(f"Incorrect padding of message-- interpreted padding of {ord(padding)} but found {ord(msg[c])} in message")
    return msg[:-padding]

#msg = "ICE ICE BABY\x04\x04\x04"
#print(pkcs7_unpad(msg))
