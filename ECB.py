from Crypto.Cipher import AES
import pkcs7
import base64
import cookiejar

BLOCKSIZE = 16

def ecb_encrypt(key, plaintext):
    # Takes in 128 bit key and plaintext in bytes
    # Returns ciphertext in bytes
    cipher = AES.new(key, AES.MODE_ECB)
    ptext = bytearray(plaintext)
    ctext = bytearray()

    plength = len(ptext)
    # Now go through each block
    for i in range(0,plength,BLOCKSIZE):
        # Select current block from plaintext that will be encrypted
        if((i+(BLOCKSIZE-1)) > plength): # Last block, time to pad
            block = ptext[i:]
            block = pkcs7.pad(block, BLOCKSIZE)
        else:
            block = ptext[i:i+BLOCKSIZE]

        # Encrypt block and add to ciphertext
        encrypted = bytearray(cipher.encrypt(bytes(block)))
        for byte in encrypted:
            ctext.append(byte)

    return bytes(ctext)
        
def ecb_decrypt(key, ciphertext):
    # Takes in 128 bit key and ciphertext in bytes
    # Returns plaintext in bytes
    # Returns error if ciphertext isn't multiple of block size or padding is done incorrectly
    cipher = AES.new(key, AES.MODE_ECB)
    ctext = bytearray(ciphertext)
    ptext = bytearray()

    clength = len(ctext)
    if(clength % BLOCKSIZE != 0):
        # ciphertext length not multiple of blocksize
        raise Exception("Ciphertext length not multiple of block size")
    
    for i in range(0, clength, BLOCKSIZE):
        # Select current block from ciphertext that will be decrypted
        if((i+BLOCKSIZE) > (clength-1)):
            # Last block
            block = ctext[i:]
            decrypted = cipher.decrypt(bytes(block))
            try:
                decrypted = bytearray(pkcs7.unpad(decrypted, BLOCKSIZE))
            except Exception as e:
                print("UNPADDING UNSUCCESSFUL: {}".format(str(e)))
        else:
            block = ctext[i:i+BLOCKSIZE]
            decrypted = bytearray(cipher.decrypt(bytes(block)))
        
        for byte in decrypted:
            ptext.append(byte)

    return bytes(ptext)

def id_ECB(ciphertext):
    # Takes in plaintext and looks for similar blocks
    # Takes advantage of ECB vulnerability where 
    # same plaintext block will result in same ciphertext block
    # Input: Ciphertext as bytearray 
    # (as opposed to bytes in other functions, since ctext will already be processed to remove header)
    # Returns True if at least one set of matching blocks found, False otherwise
    blocks = {}
    matches = 0
    for i in range(0, len(ciphertext), BLOCKSIZE):
        if(i > len(ciphertext)-1):
            block = ciphertext[i:]
        else:
            block = bytes(ciphertext[i:i+BLOCKSIZE])
        
        if(blocks.get(block) is None):
            # Ciphertext block hasn't been found yet, add to dict
            blocks[block] = 1
        else:
            matches += 1
    return (matches > 0)
    

def spoof_admin_cookie_ECB():
    # cookie is in format: user=USERNAME&uid=UID&role=ROLE
    # Using 'admin' as our username and a 1 digit UID (its an incrementing integer):
    # unencryptedcookie = user=XXXXX&uid=X &role=admin

    # End goal: construct cookie that, when decrypted, yields:
    #     user=AAAAAAAAAAA AAAA&uid=X&role= admin
    #     [    block 1   ] [    block 2   ] [    block 3   ]
    # To do this, we need to figure out what the first two blocks of the cookie give us, which is as easy as using 15 A's for out username
    username = "A" * 15
    pre_admin = cookiejar.get_auth_token({'user':username, 'password':'lmao'})[:64] # Only want first two blocks/first 32 bytes, so first 64 hex chars

    # To get our admin block, we need to account for padding, which in this case uses the ANSIX923 padding scheme
    # Since we're padding 11 bytes, need 10 \x00 bytes then a final \x0B byte to tell number of bytes to strip
    username = "A" * 11 + "admin" + 10 * b'\x00'.decode("ascii") + b'\x0B'.decode("ascii") # Fill first block, then insert admin+padding block

    admin = cookiejar.get_auth_token({'user':username, 'password':'lmao'})[32:64] # Just take our encrypted, padded block

    # So now our valid cookie will be all 3 encrypted blocks
    return pre_admin + admin
    

def main():

    print("\n########## BEGIN BASIC ECB TESTING ##########")
    TaskII_A = open("Lab2.TaskII.A.txt", 'r')
    key = 'CALIFORNIA LOVE!'.encode('ascii')

    b64encoded = TaskII_A.read().replace('\n', '')
    ciphertext = base64.b64decode(b64encoded)

    plaintext = ecb_decrypt(key, ciphertext)

    print("DECRYPTED CIPHERTEXT: \n{}\n".format(plaintext.decode('ascii')))

    ctext = ecb_encrypt(key, plaintext)
    plaintext = ecb_decrypt(key, ctext)

    print("RE-ENCRYPTED THEN DECRYPTED: \n{}\n".format(plaintext.decode('ascii')))

    TaskII_B = open("Lab2.TaskII.B.txt", 'r')
    lines = TaskII_B.readlines()

    image = open("Lab2.TaskII.B.image.bmp", 'wb')
    count = 0
    matched = []
    for line in lines:
        processed = bytes.fromhex(line[54:].strip())
        if(id_ECB(bytearray(processed)) > 0):
            image.write(bytes.fromhex(line.strip()))
            count += 1
        
    print("Number of ECB encryptions found: {}".format(count))
    print("\n##########  END BASIC ECB TESTING  ##########\n")

    print("\n######## BEGIN ECB ADMIN COOKIE GAME ########")
    login_info = spoof_admin_cookie_ECB()
    print("\nSpoofed cookie: {}\n".format(login_info))
    cookiejar.admin_login(login_info)
    print("\n########  END ECB ADMIN COOKIE GAME  ########\n")


if __name__ == '__main__':
    main()