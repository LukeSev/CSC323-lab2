def pad(message, blocksize):
    # Takes in message as byte array and blocksize as int
    # Returns padded message as byte array
    pad_size = len(message) % blocksize
    if(pad_size == 0):
        # Pad with zero block
        pad_bytes = bytearray(blocksize)
    else:
        if(len(message) < blocksize):
            pad_size = blocksize - len(message)
        pad_bytes = bytearray()
        for i in range(pad_size):
            pad_bytes.append(pad_size)
    for byte in pad_bytes:
        message.append(byte)
    return message


def main():
    test = bytearray()
    for i in range(12):
        test.append(i)
    print("Unpadded: \n{}\n".format(test))
    newtest = pad(test, 4) # Should pad with two \x02 bytes
    print("Padded: \n{}\n".format(newtest))

if __name__ == '__main__':
    main()
        