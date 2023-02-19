import random

def pad(message, blocksize):
    # Pad with all zeros except for last byte, which tells you how many bytes were padded
    msg_arr = bytearray(message)
    pad_size = blocksize - (len(msg_arr) % blocksize)

    # by number of pad bytes, then set last byte to pad size
    pad_bytes = bytearray(pad_size)
    pad_bytes[pad_size-1] = pad_size
    for byte in pad_bytes:
        msg_arr.append(byte)
    return bytes(msg_arr)

def unpad(message, blocksize):
    # Number of pad bytes is specified in last byte of message
    # Remove this number of bytes
    msg_arr = bytearray(message)
    pad_size = msg_arr[len(msg_arr)-1]

    return bytes(msg_arr[:-pad_size])


def main():
    blocksize = 8
    pad_size = 8
    numblocks = 4

    ctr = 0
    x = 2

    msg_arr = bytearray()
    for i in range(numblocks-1):
        for j in range(blocksize):
            msg_arr.append(j)
    for i in range(pad_size):
        msg_arr.append((i+1)*2)
    

    msg = bytes(msg_arr)
    padded = pad(msg, blocksize)
    print("PADDED: {}".format(padded))

    unpadded = unpad(padded, blocksize)
    print("UNPADDED: {}".format(unpadded))

if __name__ == '__main__':
    main()
