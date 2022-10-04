from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
import random
from urllib.parse import *


def verify(cipher, key, ivector, scram_list):
    box = AES.new(key, AES.MODE_CBC, iv=ivector)
    plain = unpad(box.decrypt(cipher), 16, 'pkcs7')

    tlist, scram_help = [], b''
    clist = []
    for x in range(0, len(plain), 16):
        tlist.append(plain[x:x+16])
    for c in range(0, len(cipher), 16):
        clist.append(cipher[c:c+16])

    for y in tlist:
        xorlist = bytearray()
        if scram_list[0] and y == tlist[2]:
            for z in range(len(y)):
                xorlist.append(y[z] ^ clist[1][z])
            xor_calc = bytes(a ^ b for (a, b) in zip(xorlist, xorlist))
            xor_final = bytes(a ^ b for (a, b) in zip(xor_calc, b';admin=true;'))
            print(xor_final)
            scram_help += xor_final
            tlist[2] = scram_help
            plain = b''
            for item in tlist:
                plain += item
            
    print(tlist)
    return b'%3Badmin%3Dtrue%3B' in plain or b';admin=true;' in plain
    

def cbc_encryption(uinput, box, ivector, scram_list):
    # output ciphertext
    ciphertext = b''

    clist = []
    for x in range(0, len(uinput), 16):
        clist.append(uinput[x:x+16])

    for y in clist:
        xorlist = bytearray()
        for index in range(len(y)):
                xorlist.append(y[index] ^ ivector[index])       
        
        ivector = box.encrypt(xorlist)
        # XORing again to byte flip
        if scram_list[0] and y == clist[1]:
            xorlist = bytes(a ^ b for (a, b) in zip(ivector, clist[1])) 
            ivector = box.encrypt(xorlist)

        ciphertext += (ivector)
    
    return ciphertext


def submit(udata, uinput, sessionid, box, ivector, scram_list):
    if ';admin=true;' in uinput:
        uinput = uinput.replace(";admin=true;", "")

    # Concatenating pieces together, after URL encoding
    uinput = (udata + uinput + sessionid).replace\
                    ("=", quote("=")).replace(";", quote(";"))

    # padding input and saving it for later
    uinput = pad(uinput.encode('ascii'), 16, style='pkcs7')
    # scram_list[1] = uinput

    return cbc_encryption(uinput, box, ivector, scram_list)
    

def main():
    # KEYS
    key_cbc = get_random_bytes(16)

    # VECTOR (will also store the previous cipher for ease of access)
    ivector = get_random_bytes(16)

    # Encryption used for each block
    box = AES.new(key_cbc, AES.MODE_ECB)

    udata = 'userid=' + str(random.randint(100, 999)) + ';'
    sessionid = ';session-id=' + str(random.randint(10000, 99999))
    uinput = "userdata=" + input("Input string for encryption: ")

    # Last parameter list is used to distinguish between nonscrambled
    # and scrambled versions of the encryption/decryption process
    scram_true = [True, b'']
    scram_false = [False, b'']

    # running code normally, expected to return false
    cipher = submit(udata, uinput, sessionid, box, ivector, scram_false)
    print(verify(cipher, key_cbc, ivector, scram_false))

    # getting verify to return true
    scrambled_cipher = submit(udata, uinput, sessionid, box, ivector, scram_true)
    print(verify(scrambled_cipher, key_cbc, ivector, scram_true))






if __name__ == "__main__":
    main()