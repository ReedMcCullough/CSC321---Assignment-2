from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
from urllib.parse import *
import random

def verify(cipher, key, ivector, scram_bool):
    # CBC encryptor and the plain text after decryption
    box = AES.new(key, AES.MODE_CBC, iv=ivector)
    plain = unpad(box.decrypt(cipher), 16, 'pkcs7')

    # splitting the plain and cipher text back into blocks
    # for easier access
    tlist, scram_help = [], b''
    clist = []
    for x in range(0, len(plain), 16):
        tlist.append(plain[x:x+16])
    for c in range(0, len(cipher), 16):
        clist.append(cipher[c:c+16])

    # special case for ';admin=true;'
    for y in tlist:
        xorlist = bytearray()

        # testing for if the loop is at i+1 block and if
        # is the correct time to trick the verify() function
        if scram_bool and y == tlist[2]:
            # A XOR B = C
            for z in range(len(y)):
                xorlist.append(y[z] ^ clist[1][z])

            # A XOR B = C
            # A XOR B XOR C = 0
            # C XOR C = 0
            # C XOR C XOR 'desired output' = 'desired output'
            xor_calc = bytes(a ^ b for (a, b) in zip(xorlist, xorlist))
            xor_final = bytes(a ^ b for (a, b) in zip(xor_calc, b';admin=true;'))
            scram_help += xor_final
            # replace inside plaintext
            tlist[2] = scram_help
            plain = b''
            for item in tlist:
                plain += item
            
    print(plain)
    return b'%3Badmin%3Dtrue%3B' in plain or b';admin=true;' in plain
    

def cbc_encryption(uinput, box, ivector, scram_bool):
    # output ciphertext
    ciphertext = b''

    clist = [] # splitting input for easier access
    for x in range(0, len(uinput), 16):
        clist.append(uinput[x:x+16])

    for y in clist:
        xorlist = bytearray()
        for index in range(len(y)):
                xorlist.append(y[index] ^ ivector[index])       
        
        ivector = box.encrypt(xorlist)
        # XORing again to byte flip
        if scram_bool and y == clist[1]:
            xorlist = bytes(a ^ b for (a, b) in zip(ivector, clist[1])) 
            ivector = box.encrypt(xorlist)

        ciphertext += (ivector)
    
    return ciphertext


def submit(udata, uinput, sessionid, box, ivector, scram_bool):
    # removing ';admin=true;' if inside user input, shouldn't be
    # a part of the submit()/verify() functionality
    if ';admin=true;' in uinput:
        uinput = uinput.replace(";admin=true;", "")

    # Concatenating pieces together, after URL encoding
    uinput = (udata + uinput + sessionid).replace\
                    ("=", quote("=")).replace(";", quote(";"))

    # padding input and saving it for later
    uinput = pad(uinput.encode('ascii'), 16, style='pkcs7')
    return cbc_encryption(uinput, box, ivector, scram_bool)
    

def main():
    # KEYS (128 bits)
    key_cbc = get_random_bytes(16)

    # VECTOR (will also store the previous cipher for ease of access)
    ivector = get_random_bytes(16)

    # Encryption used for each block
    box = AES.new(key_cbc, AES.MODE_ECB)

    udata = 'userid=' + str(random.randint(100, 999)) + ';'
    sessionid = ';session-id=' + str(random.randint(10000, 99999))
    print()
    uinput = "userdata=" + input("Input string for encryption: ")
    print()

    # Last parameter boolean is used to distinguish between nonscrambled
    # and scrambled versions of the encryption/decryption process

    # running code normally, expected to return false
    print('--- Normal Process ---')
    cipher = submit(udata, uinput, sessionid, box, ivector, False)
    verify_normal = verify(cipher, key_cbc, ivector, False)
    print("admin string present? -> " + str(verify_normal))
    print()

    # tricking verify to return true despite same input
    print('*** Tricking verify() function with bit flipping ***')
    scrambled_cipher = submit(udata, uinput, sessionid, box, ivector, True)
    verify_trick = verify(scrambled_cipher, key_cbc, ivector, True)
    print("admin string present? -> " + str(verify_trick))
    print()






if __name__ == "__main__":
    main()