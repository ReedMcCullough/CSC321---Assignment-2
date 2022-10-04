from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
import random
from urllib.parse import *


def verify(cipher, key, ivector, scram_tuple):
    box = AES.new(key, AES.MODE_CBC, iv=ivector)
    plain = unpad(box.decrypt(cipher), 16, 'pkcs7')

    tlist, scram_help = [], b''
    for x in range(0, len(plain), 16):
        tlist.append(plain[x:x+16])

    for y in tlist:
        xorlist = bytearray()
        if scram_tuple[0] and y == tlist[2]:
            for z in range(len(y)):
                xorlist.append(y[z] ^ scram_tuple[1][z])
            scram_help += xorlist
            tlist[2] = scram_help
            
    print(tlist)
    return b'%3Badmin%3Dtrue%3B' in plain
    

def cbc_encryption(uinput, box, ivector, scram_tuple):
    # output ciphertext
    ciphertext = b''

    clist = []
    for x in range(0, len(uinput), 16):
        clist.append(uinput[x:x+16])

    for y in clist:
        xorlist = bytearray()

        if scram_tuple[0] and y == clist[1]:
            for z in range(len(y)):
                xorlist.append((y[z] ^ ivector[z]) ^ scram_tuple[1][z])
        else:
            for index in range(len(y)):
                xorlist.append(y[index] ^ ivector[index])
        
        ivector = box.encrypt(xorlist)
        # print("ivector: " + str(ivector))
        ciphertext += (ivector)
    
    return ciphertext


def submit(udata, uinput, sessionid, box, ivector, scram_tuple):
    if ';admin=true;' in uinput:
        uinput = uinput.replace(";admin=true;", "")

    uinput = (udata + uinput + sessionid).replace\
                    ("=", quote("=")).replace(";", quote(";"))

    uinput = pad(uinput.encode('ascii'), 16, style='pkcs7')

    if scram_tuple[0]:
        answer = cbc_encryption(uinput, box, ivector, scram_tuple)
        slist = []
        for x in range(0, len(answer), 16):
            slist.append(answer[x:x+16])
        # print("-- slist -- " + str(slist))
        return answer
    else:
        return cbc_encryption(uinput, box, ivector, scram_tuple)
    

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

    # Last parameter tuple is used to distinguish between nonscrambled
    # and scrambled versions of the encryption/decryption process
    scram_true = (True, get_random_bytes(16))
    scram_false = (False, b'')

    cipher = submit(udata, uinput, sessionid, box, ivector, scram_false)
    print(verify(cipher, key_cbc, ivector, scram_false))

    # getting verify to return true
    scrambled_cipher = submit(udata, uinput, sessionid, box, ivector, scram_true)
    print(verify(scrambled_cipher, key_cbc, ivector, scram_true))






if __name__ == "__main__":
    main()