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
        if(i > (clength-1)):
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
    # unencryptedcookie = user=XXXXX&uid=X&role=...

    # Since we know it's using ECB, we can figure out what the beginning of the admin's cookie will look like (excluding not-allowed characters '&' and '=')
    payload_username = "adminXuidX0XroleXadmin"
    # cookie format: user=admin  XuidX0Xrol  eXadmin &uid=...
    # indexing:      0123456789  0123456789  0123456 789...
    # decimal       0           1           2
    payload_params = {'user':payload_username, 'password':"doesntmatter"}

    cookie = cookiejar.get_auth_token(payload_params)

    # Using the formatting above, we can figure out different parts of what a valid admin cookie can look like:
    user_admin_enc = cookie[:10]
    uid_field_admin_enc = cookie[11:14]
    uid_val_admin_enc = cookie[15]
    role_field_admin_enc = cookie[17:21]
    role_val_admin_enc = cookie[22:27]
    
    # Now we have every part of the admin's cookie except the special characters, which we can get by generating a cookie for a generic 5-char user
    special_char_params = {'user':'12345', 'password':'lmao'}
    # Cookie format: user=12345 &uid=1&rol e=user [rest of cookie]
    # indexing:      0123456789 0123456789 012345 6...
    # decimal:      0          1          2           

    spec_cookie = cookiejar.get_auth_token(special_char_params)
    uid_amp_enc = spec_cookie[10]
    uid_eq_enc = spec_cookie[14]
    role_amp_enc = spec_cookie[16]
    role_eq_enc = spec_cookie[21]

    # For the rest of the cookie, we need a new token generated with a 6 character username
    # This is because the second block is padded with ansix923, which depends on the number of characters it needs to pad
    # To emulate what the padding would look like for the admin, we simply input any 6 char username (to accound for the 1 missing char between role=admin and role=user)
    final_params = {'user':'123456', 'password':'sendhelp'}
    rest_of_cookie = cookiejar.get_auth_token(final_params)[27:]

    # Now we reconstruct our spoofed cookie
    spoofed_cookie = user_admin_enc + uid_amp_enc + uid_field_admin_enc + uid_eq_enc + uid_val_admin_enc + role_amp_enc + role_field_admin_enc + role_eq_enc + role_val_admin_enc + rest_of_cookie
    return spoofed_cookie

def main():

    login_info = spoof_admin_cookie_ECB()
    print("Admin Cookie: {}".format(login_info))
    cookiejar.admin_login(login_info)


    # TaskII_A = open("Lab2.TaskII.A.txt", 'rb')
    # key = 'CALIFORNIA LOVE!'.encode('ascii')

    # b64encoded = TaskII_A.read().strip()
    # ciphertext = base64.b64decode(b64encoded)
    # plaintext = ecb_decrypt(key, ciphertext)

    # print("DECRYPTED CIPHERTEXT: \n{}\n".format(plaintext.decode('ascii')))

    # ctext = ecb_encrypt(key, plaintext)
    # plaintext = ecb_decrypt(key, ctext)

    # print("RE-ENCRYPTED THEN DECRYPTED: \n{}\n".format(plaintext.decode('ascii')))

    # TaskII_B = open("Lab2.TaskII.B.txt", 'r')
    # lines = TaskII_B.readlines()

    # image = open("Lab2.TaskII.B.image.bmp", 'wb')
    # count = 0
    # matched = []
    # for line in lines:
    #     processed = bytes.fromhex(line[54:].strip())
    #     if(id_ECB(bytearray(processed)) > 0):
    #         image.write(bytes.fromhex(line.strip()))
    #         count += 1
        
    # print("Number of ECB encryptions found: {}".format(count))


if __name__ == '__main__':
    main()