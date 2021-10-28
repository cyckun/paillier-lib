from typing import Mapping
import paillier_bind
import time

def paillier_test():

    plain = []
    new_plain = []
    cipher = []
    for i in range(32):
        plain.append(32 - i)  # 0 is not ok, don't know why

    c = paillier_bind.Paillier_bind()
    begin = time.time()
    for i  in range(1000):
        c.Paillier_GenKey()
        #print("key gen time = ", time.time() - begin)
        # begin_enc = time.time()
        cipher = c.Paillier_Encrypt(plain, cipher)
        #print("encrypt time = ", time.time() - begin_enc)
        # print("cipher = ",  cipher)
        new_plain = c.Paillier_Decrypt(cipher, new_plain)
        i = i+1
    print("decrypt time = ", time.time() - begin)
    # print("plain = ",  new_plain)
    # assert(plain == new_plain)

if __name__ == '__main__':
    paillier_test()