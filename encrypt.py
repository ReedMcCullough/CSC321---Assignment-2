from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *


def main():

    # KEYS (128 bits)
    key_ecb = get_random_bytes(16)
    key_cbc = get_random_bytes(16)

    # VECTOR (will also store the previous cipher for ease of access)
    ivector = get_random_bytes(16)

    file_in = open("cp-logo.bmp", "rb")

    # read and preserve header for later
    header = file_in.read(54)

    # read rest of the file
    f = file_in.read()
    file_in.close()

    # pad file for encryption blocks
    f = pad(f, 16, style='pkcs7')
    split = []
    clist = []

    # 'split' input for every 16 bytes, save in list for easier iteration
    for i in range(0, len(f), 16):
        split.append(f[i:i+16])
        clist.append(f[i:i+16])



    # (ECB CODE) write to output file after encrypting
    file_out, ecb_box = open("ecb_output.bmp", "wb"), AES.new(key_ecb, AES.MODE_ECB)
    file_out.write(header)
    for x in split:
        file_out.write(ecb_box.encrypt(x))
    file_out.close()



    # (CBC CODE) write to output file after XORing the plaintext with either
    # the Initialization vector or the previous cipher text, then
    # encrypting that output
    file_out, cbc_box = open("cbc_output.bmp", "wb"), AES.new(key_cbc, AES.MODE_ECB)
    file_out.write(header)
    for x in clist:
        xorlist = bytearray()

        for index in range(len(x)):
            xorlist.append(x[index] ^ ivector[index])

        ivector = cbc_box.encrypt(xorlist)
        file_out.write(ivector)
    file_out.close()


    
    


if __name__ == "__main__":
    main()