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

    if(len(ciphertext) % BLOCKSIZE != 0):
        raise Exception("Ciphertext is not a multiple of the block size")

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

def spoof_admin_cookie_CBC():
    # Our attack will go as follows:
    # Starting plaintext:  user=AAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA &uid=1&role=user [padding block]
    # Goal plaintext:      user=AAAAAAAAAAA [   gibberish  ] &uid=0&AAAAAAA=A [   gibberish  ] &role=admin&A=AA [   gibberish  ] [padding block]
    # Block #:             [    block1    ] [    block2    ] [    block3    ] [    block4    ] [    block4    ] [    block4    ] [padding block]

    # To accomplish this, we will need to XOR the ciphertext block in block2 starting at index 5 (where the '1' is in block3 of plaintext)
    # To get the plaintext to become what we want, we need to XOR each byte in ciphertext with (starting plaintext byte ^ goal plaintext byte) for the byte at the corresponding index

    # We can do this because the server doesn't check for the validity or count of the fields that are submitted but just the three that it looks for
    # As such, we can do byte flipping on however many blocks we want as long as it results in the query parser finding a user, uid, and role field
    # The query parser uses '&' as a separator, so we just have to make sure we set them around the info we want

    # Now we need to actually generate the ciphertext:
    cookie = bytearray.fromhex(cookiejar.get_auth_token({'user':"A" * (11+(16*4)), 'password':'lol'}))
    
    # First round of payload insertion takes care of uid
    chars_to_change = "AAAAAAAAAAAAAAAA"
    goal_chars = "&uid=0&AAAAAAA=A"
    payload = fill_payload(chars_to_change, goal_chars)
    cookie = insert_payload(cookie, payload, 32)

    # Second round of payload insertion takes care of role
    chars_to_change = "AAAAAAAAAAAAAAAA"
    goal_chars = "&role=admin&A=AA"
    payload = fill_payload(chars_to_change, goal_chars)
    cookie = insert_payload(cookie, payload, 64)

    return bytes(cookie).hex()

def fill_payload(str1, str2):
    # Given strings of equal length, create bytearray that represents...
    # a block comprised of each element in str1 XORed with each corresponds to element in str2
    # Note: Since ascii string, XOR their ascii values
    payload = bytearray(BLOCKSIZE-len(str1))
    for i in range(len(str1)):
        payload.append(ord(str1[i]) ^ ord(str2[i]))
    return payload

def insert_payload(ciphertext, payload, start):
    # Takes in ciphertext and payload as bytearray
    for i in range(start, start+BLOCKSIZE, 1):
        ciphertext[i] = ciphertext[i] ^ payload[i-start]
    return ciphertext

def main():
    # If you only want to test one part of TaskIII, set the part(s) you don't want tested to false below
    # part1 corresponds to the basic CBC decryption, part2 the admin cookie-spoofing
    part1 = True
    part2 = True

    if(part1):
        print("\n#####   BEGIN CBC DECRYPTION   #####\n")
        file = open("Lab2.TaskIII.A.txt", 'r')
        b64encoded = file.read().replace('\n', '')
        ciphertext = base64.b64decode(b64encoded)[16:] # Remove first block

        key = 'MIND ON MY MONEY'.encode("ascii")
        IV = 'MONEY ON MY MIND'.encode("ascii")

        plaintext = cbc_decrypt(ciphertext, key, IV)
        print(plaintext.decode())
        print("\n#####    END CBC DECRYPTION    #####\n")

    if(part2):
        print("\n##### BEGIN CBC ADMIN SPOOFING #####\n")
        
        spoofed_cookie = spoof_admin_cookie_CBC()
        print("Admin Cookie: {}".format(spoofed_cookie))
        cookiejar.admin_login(spoofed_cookie)

        print("\n#####  END CBC ADMIN SPOOFING  #####\n")

if __name__ == "__main__":
    main()
