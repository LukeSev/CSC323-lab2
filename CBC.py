from Crypto.Cipher import AES
import pkcs7
import base64
import cookiejar

BLOCKSIZE = 16

def cbc_encrypt(plaintext, key, IV):
    # Takes in plaintext, key, and IV as bytes
    # Returns ciphertext as bytes
    # Assumes IV needs to be first block in ciphertext

    cipher = AES.new(key, AES.MODE_ECB) # will manually do ECB mode encryption on each block but input will change based on CBC

    ptext = bytearray(plaintext)
    ctext = bytearray()
    plength = len(ptext)
    prev = bytearray(IV) # Will XOR with previous ctext for each round, starting with IV

    # First block is IV, as is customary
    for byte in prev:
        ctext.append(byte)

    for i in range(0, plength, BLOCKSIZE):
        # Select current block from plaintext that will be encrypted
        if((i+(BLOCKSIZE-1)) > plength):
            mblock = ptext[i:]
            mblock = pkcs7.pad(mblock, BLOCKSIZE)
        else:
            mblock = ptext[i:i+BLOCKSIZE]

        # XOR each byte in mblock with each byte in previous block
        # This will build the block that will act as the plaintext in each iteration of ECB encryption
        pblock = bytearray()
        for j in range(BLOCKSIZE):
            pblock.append(mblock[j] ^ prev[j]) # XOR each byte with corresponding byte in previous block
        
        # Now get encrypted ciphertext block cblock and add to ciphertext
        cblock = bytearray(cipher.encrypt(bytes(pblock)))
        for byte in cblock:
            ctext.append(byte)

        # Set new previous block
        prev = cblock

    return bytes(ctext)


def cbc_decrypt(ciphertext, key, IV):
    # Takes in ciphertext, key, and IV as bytes
    # Returns plaintext as bytes
    # Assumes IV has already been removed from first block of original ciphertext

    cipher = AES.new(key, AES.MODE_ECB)

    ctext = bytearray(ciphertext)
    ptext = bytearray()
    clength = len(ctext)
    prev = bytearray(IV) # Will XOR result of each decryption with previous ctext block, starting with IV

    for i in range(0, clength, BLOCKSIZE):
        intermed = bytearray()
        # Select current block from ciphertext that will be decrypted
        if((i+BLOCKSIZE) > (clength-1)):
            # Last block
            cblock = ctext[i:i+BLOCKSIZE]
            decrypted = bytearray(cipher.decrypt(bytes(cblock)))
            for j in range(BLOCKSIZE):
                intermed.append(decrypted[j] ^ prev[j])
            try:
                intermed = bytearray(pkcs7.unpad(bytes(intermed), BLOCKSIZE))
            except Exception as e:
                print("UNPADDING UNSUCCESSFUL: {}".format(str(e)))
        else:
            cblock = ctext[i:i+BLOCKSIZE]
            decrypted = bytearray(cipher.decrypt(bytes(cblock)))
            # XOR decrypted block with previous block to get each byte in block of plaintext
            for j in range(BLOCKSIZE):
                intermed.append(decrypted[j] ^ prev[j])
        for byte in intermed:
            ptext.append(byte)
        prev = cblock
    return bytes(ptext)

def main():
    file = open("Lab2.TaskIII.A.txt", 'r')
    b64encoded = file.read().replace('\n', '')
    ciphertext = base64.b64decode(b64encoded)[16:] # Remove first block

    key = 'MIND ON MY MONEY'.encode("ascii")
    IV = 'MONEY ON MY MIND'.encode("ascii")

    plaintext = cbc_decrypt(ciphertext, key, IV)
    print(plaintext.decode())

if __name__ == "__main__":
    main()
