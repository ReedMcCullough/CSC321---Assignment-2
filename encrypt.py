from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *


def main():
    key = get_random_bytes(16)
    print(key)
    box = AES.new(key, AES.MODE_ECB)
    




if __name__ == "__main__":
    main()