#include <iostream>
#include <pybind11/pybind11.h>
#include <vector>
#include <pybind11/stl.h>
#include <openssl/evp.h>
#include "paillier.h"

using namespace std;


class Paillie{
  public:
    Paillie() {}
    int GenKey() {

      Paillier paillier;
      
      unsigned char buffer[1024] = {0};
      int kbits = 1024;
      /* generate key pair */
      if (!(key = paillier.PAILLIER_new())) {
        std::cout << "PAILLIER_NEW fail." << std::endl;
      }
      if (!paillier.PAILLIER_generate_key(key, kbits)) {
        std::cout << "PAILLIER_generate_key fail." << std::endl;
      }
      
      // BN_print_fp(stdout, key->n);

      int count = 0;
      BN_bn2bin(key->n, buffer);
      for (int i = 0; i < 128; i++) {
        if (buffer[i]) count++;
      }
      // printf("size = %d", count);
      // BN_print_fp(stdout, key->lambda);
    
      return 0;
    }
  vector<int> Encrypt(vector<int>& plain, vector<int>& cipher) {

    // for (int i = 0; i < 32; i++) printf("%02x", plain[i]);
    BIGNUM *m1 = NULL;
    BIGNUM *c1 = NULL;
    unsigned char msg[257];
    for (int i = 0; i < 32; ++i) {
        msg[i] = plain[i];
    }

    m1 = BN_new();
    c1 = BN_new();

    m1 = BN_bin2bn(msg, 32, m1);
    Paillier paillier;
    if (!paillier.PAILLIER_encrypt(c1, m1, key)) {
      // return -1;
    }
    BN_bn2bin(c1, msg);
    int j = BN_num_bytes(c1);
    // printf(" j = %d", j);
    for (int i = 0; i < j; ++i) {
      cipher.push_back(msg[i]);
    }
    // paillier.PAILLIER_free(key);
    // BN_free(c1);
    // BN_free(m1);

    return cipher;
  }

  vector<int> Decrypt(vector<int>& cipher, vector<int>& plain) {
    BIGNUM *m1 = NULL;
    BIGNUM *c1 = NULL;
    int cipher_len = 256;
    unsigned char msg[cipher_len + 1];
    
    for (int i = 0; i < cipher_len; ++i) {
        msg[i] = (unsigned char)cipher[i];
    }

    m1 = BN_new();
    c1 = BN_new();

    m1 = BN_bin2bn(msg, 256, c1);
    Paillier paillier;
    if (!paillier.PAILLIER_decrypt(m1, c1, key)) {
      // return -1;
    }
    BN_bn2bin(m1, msg);
    int j = BN_num_bytes(m1);
    for (int i = 0; i < j; ++i) {
      plain.push_back(msg[i]);
    }

     // paillier.PAILLIER_free(key);
    //BN_free(c1);
    // BN_free(m1);
    
    return plain;
  }

  private:
    int key_bits = 1024;
    PAILLIER *key = NULL;
};

PYBIND11_MODULE(paillier_bind, m) {
  m.doc() = "pybind11 example plugin"; // optional module docstring
    
  pybind11::class_<Paillie>(m , "Paillier_bind")
    .def(pybind11::init())
    .def("Paillier_GenKey", &Paillie::GenKey)
    .def("Paillier_Encrypt", &Paillie::Encrypt)
    .def("Paillier_Decrypt", &Paillie::Decrypt);
}






