#include <iostream>
#include <pybind11/pybind11.h>
#include <vector>
#include <pybind11/stl.h>
#include <openssl/evp.h>
#include "paillier.h"

using namespace std;

int add(int i, int j) {
    return i + j;
}

vector<int> Paillier_GenKey(vector<int>& out_list) {

  Paillier paillier;
  PAILLIER *key = NULL;
  unsigned char buffer[128] = {0};
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
  printf("size = %d", count);
  // BN_print_fp(stdout, key->lambda);
  for (int i = 0; i < count ; ++i) 
    out_list.push_back(buffer[i]);
  return out_list;
}


PYBIND11_MODULE(paillier_bind, m) {
    m.doc() = "pybind11 example plugin"; // optional module docstring

    m.def("add", &add, "A function which adds two numbers");
    m.def("Paillier_GenKey", &Paillier_GenKey, "generate key");
}





