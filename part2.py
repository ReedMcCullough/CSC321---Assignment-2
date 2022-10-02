from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
import random
from urllib.parse import *


def verify(cipher, key, ivector):
    box = AES.new(key, AES.MODE_CBC, iv=ivector)
    print(box.decrypt(cipher))
    

def cbc_encryption(uinput, box, ivector):
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
        
        ciphertext += (ivector)
    return ciphertext


def submit(udata, uinput, sessionid, box, ivector):

    uinput = udata + uinput + sessionid
    for x in range(len(uinput)):
        if uinput[x] == ';' or uinput[x] == '=':
            uinput = uinput[:x] + quote(uinput[x]) + uinput[x+1:]

    uinput = pad(uinput.encode('ascii'), 16, style='pkcs7')
    return cbc_encryption(uinput, box, ivector)
    

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

    cipher = submit(udata, uinput, sessionid, box, ivector)
    verify(cipher, key_cbc, ivector)







if __name__ == "__main__":
    main()