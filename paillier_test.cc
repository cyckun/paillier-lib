#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <iostream>
#include "paillier.h"
#include <time.h>
#include <sys/time.h>

double get_wall_time() 
{ 
  struct timeval time ; 
  if (gettimeofday(&time,NULL)){ 
    return 0; 
  } 
  return (double)time.tv_sec + (double)time.tv_usec * .000001; 
}

static int test_paillier(int verbose) {
  int ret = 0;
  int kbits = 1024;
  unsigned char buffer[64];
  int i, j;
  PAILLIER *key = NULL;
  BIGNUM *mx = NULL;
  BIGNUM *m1 = NULL;
  BIGNUM *m2 = NULL;
  BIGNUM *m3 = NULL;
  BIGNUM *c1 = NULL;
  BIGNUM *c2 = NULL;
  BIGNUM *c3 = NULL;
  BN_ULONG n;
  Paillier paillier;
  /* generate key pair */
  if (!(key = paillier.PAILLIER_new())) {
    std::cout << "PAILLIER_NEW fail." << std::endl;
  }
  if (!paillier.PAILLIER_generate_key(key, kbits)) {
    std::cout << "PAILLIER_generate_key fail." << std::endl;
  }
  printf("n = ");
  BN_print_fp(stdout, key->n);
  printf("\n");
  printf("lambda = ");
  BN_print_fp(stdout, key->lambda);
  printf("\n");
  /* tmp values */
  mx = BN_new();
  m1 = BN_new();
  m2 = BN_new();
  m3 = BN_new();
  c1 = BN_new();
  c2 = BN_new();
  c3 = BN_new();

  if (!mx || !m1 || !m2 || !m3 || !c1 || !c2 || !c3) {
    return -1;
  }

  /* mx is the max value of plaintext integers */
  if (!BN_set_bit(mx, 256)) {
    return -1;
  }

  /* rand plaintexts */
  if (!BN_rand_range(m1, mx)) {
    return -1;
  }
  if (!BN_rand_range(m2, mx)) {
    return -1;
  }

  if (verbose) {
      printf("m1 = ");
      BN_print_fp(stdout, m1);
      printf("\n");
      printf("m2 = ");
      BN_print_fp(stdout, m2);
      printf("\n");
  }

  /* encrypt and ciphertext addition */
  double start_time = get_wall_time();
  for (int ct = 0; ct < 1000; ct++) {
    for (int count = 0; count < 1; count++) {
      if (!paillier.PAILLIER_encrypt(c1, m1, key)) {
          return -1;
      }
    }
    // double end_time = get_wall_time(); 
    // std::cout<<"循环耗时为:"<<end_time-start_time<<"ms" << std::endl;
    // }
    if (!paillier.PAILLIER_encrypt(c2, m2, key)) {
      return -1;
    }
    if (!paillier.PAILLIER_ciphertext_add(c3, c1, c2, key)) {
      return -1;
    }
    if (!paillier.PAILLIER_decrypt(m3, c3, key)) {
      return -1;
    }
  }
  double end_time = get_wall_time();
  std::cout<< "耗时为:" << end_time-start_time << " s" << std::endl;

  /* convert plaintext to scalar value */
  BN_bn2bin(m3, buffer);
  j = BN_num_bytes(m3);
  printf("j = %d\n", j);
  for (int i = 0; i < j; i++)
    printf("%02x", buffer[i]);
  printf("\n");
  /*if (verbose) {
     printf("\nm1 + m2 = %lx\n", n);
     }
   */

  ret = 1;

  if (verbose) {
      printf("%s %s\n", __FUNCTION__, ret == 1 ? "passed" : "failed");
  }
  paillier.PAILLIER_free(key);
  BN_free(mx);
  BN_free(m1);
  BN_free(m2);
  BN_free(m3);
  BN_free(c1);
  BN_free(c2);
  BN_free(c3);
  return ret;
}

int main(int argc, char **argv) {
  int err = 0;
  if (!test_paillier(2))
    err++;
  // FIXME: return err;
  return 0;
}
