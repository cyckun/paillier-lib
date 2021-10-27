/*
 * Copyright[2019] <Copyright crypto-lib>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "paillier.h"

Paillier::Paillier() {
}

PAILLIER *Paillier::PAILLIER_new(void) {
  PAILLIER *ret = NULL;
  if (!(ret = reinterpret_cast < PAILLIER * >(OPENSSL_zalloc(sizeof(*ret))))) {
      return NULL;
  }
  return ret;
}

void Paillier::PAILLIER_free(PAILLIER * key) {
  if (key) {
      BN_free(key->n);
      BN_free(key->lambda);
      BN_free(key->n_squared);
      BN_free(key->n_plusone);
      BN_free(key->x);
  }
  OPENSSL_clear_free(key, sizeof(*key));
}

int Paillier::PAILLIER_size(const PAILLIER * key) {
  ASN1_INTEGER a;
  unsigned char buf[4] = { 0xff };
  int i;

  if (!(i = BN_num_bytes(key->n))) {
      return 0;
  }
  a.length = i * 2;
  a.data = buf;
  a.type = V_ASN1_INTEGER;

  return i2d_ASN1_INTEGER(&a, NULL);
}

int Paillier::PAILLIER_security_bits(const PAILLIER * key) {
  return BN_security_bits(BN_num_bits(key->n) / 2, -1);
}

int Paillier::PAILLIER_generate_key(PAILLIER * key, int bits) {
  int ret = 0;
  BIGNUM *p = NULL;
  BIGNUM *q = NULL;
  BN_CTX *bn_ctx = NULL;

  p = BN_new();
  q = BN_new();
  bn_ctx = BN_CTX_new();

  if (!key->n)
    key->n = BN_new();
  if (!key->lambda)
    key->lambda = BN_new();
  if (!key->n_squared)
    key->n_squared = BN_new();
  if (!key->n_plusone)
    key->n_plusone = BN_new();
  if (!key->x)
    key->x = BN_new();

  if (!p || !q || !bn_ctx || !key->n || !key->lambda ||
      !key->n_squared || !key->n_plusone || !key->x) {
      goto end;
  }

  key->bits = bits;
  do {
      if (!BN_generate_prime_ex(p, bits / 2, 0, NULL, NULL, NULL)) {
        goto end;
      }

      if (!BN_generate_prime_ex(q, bits / 2, 0, NULL, NULL, NULL)) {
        goto end;
      }

      if (!BN_mul(key->n, p, q, bn_ctx)
          || !BN_sub_word(p, 1) || !BN_sub_word(q, 1)
	  /*
	   * lambda = (p - 1)*(q - 1) 
	   */
          || !BN_mul(key->lambda, p, q, bn_ctx)
	  /*
	   * n_squared = n^2 
	   */
          || !BN_sqr(key->n_squared, key->n, bn_ctx)
	  /*
	   * n_plusone = n + 1 
	   */
          || !BN_copy(key->n_plusone, key->n)
          || !BN_add_word(key->n_plusone, 1)
	  /*
	   * x = (((g^lambda mod n^2) - 1)/n)^-1 mod n 
	   */
          || !BN_mod_exp(key->x, key->n_plusone, key->lambda,
                         key->n_squared, bn_ctx)
          || !BN_sub_word(key->x, 1)
          || !BN_div(key->x, NULL, key->x, key->n, bn_ctx)
          || !BN_mod_inverse(key->x, key->x, key->n, bn_ctx)) {
          goto end;
     }
  }
  while (0);

  ret = 1;

end:
  BN_clear_free(p);
  BN_clear_free(q);
  return ret;
}

int Paillier::PAILLIER_check_key(PAILLIER * key) {
  return 0;
}

int Paillier::PAILLIER_encrypt(BIGNUM * c, const BIGNUM * m, PAILLIER * pub_key) {
  int ret = 0;
  BIGNUM *r = NULL;
  BN_CTX *bn_ctx = NULL;

  if (BN_cmp(m, pub_key->n) >= 0) {
     goto end;
  }

  r = BN_new();
  bn_ctx = BN_CTX_new();
  if (!r || !bn_ctx) {
     goto end;
  }

  do {
    if (!BN_rand_range(r, pub_key->n)) {
      goto end;
    }
  }
  while (BN_is_zero(r));


  if (!pub_key->n_plusone) {
    if (!(pub_key->n_plusone = BN_dup(pub_key->n))) {
       goto end;
    }
    if (!BN_add_word(pub_key->n_plusone, 1)) {
      BN_free(pub_key->n_plusone);
      pub_key->n_plusone = NULL;
      goto end;
    }
  }

  if (!pub_key->n_squared) {
      if (!(pub_key->n_squared = BN_new())) {
        goto end;
      }
      if (!BN_sqr(pub_key->n_squared, pub_key->n, bn_ctx)) {
        BN_free(pub_key->n_squared);
        pub_key->n_squared = NULL;
        goto end;
      }
  }

  if (!BN_mod_exp(c, pub_key->n_plusone, m, pub_key->n_squared, bn_ctx)) {
      goto end;
  }

  if (!BN_mod_exp(r, r, pub_key->n, pub_key->n_squared, bn_ctx)) {
    goto end;
  }

  if (!BN_mod_mul(c, c, r, pub_key->n_squared, bn_ctx)) {
     // PAILLIERerr(PAILLIER_F_PAILLIER_ENCRYPT, ERR_R_BN_LIB);
     goto end;
  }
  ret = 1;
end:
  BN_clear_free(r);
  BN_CTX_free(bn_ctx);
  return ret;
}

int Paillier::PAILLIER_decrypt(BIGNUM * m, const BIGNUM * c, PAILLIER * key) {
  int ret = 0;
  BN_CTX *bn_ctx = NULL;

  if (!(bn_ctx = BN_CTX_new())) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_BN_LIB);
      goto end;
  }

  if (!key->n_squared) {
    if (!(key->n_squared = BN_new())) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_MALLOC_FAILURE);
      goto end;
    }
    if (!BN_sqr(key->n_squared, key->n, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_BN_LIB);
      goto end;
    }
  }

  if (!BN_mod_exp(m, c, key->lambda, key->n_squared, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_BN_LIB);
      goto end;
  }

  if (!BN_sub_word(m, 1)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_BN_LIB);
      goto end;
  }

  if (!BN_div(m, NULL, m, key->n, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_BN_LIB);
      goto end;
  }

  if (!BN_mod_mul(m, m, key->x, key->n, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_DECRYPT, ERR_R_BN_LIB);
      goto end;
  }

  ret = 1;
end:
  BN_CTX_free(bn_ctx);
  return ret;
}

int Paillier::PAILLIER_ciphertext_add(BIGNUM * r, const BIGNUM * a, const BIGNUM * b, PAILLIER * key) {
  int ret = 0;
  BIGNUM *k = NULL;
  BN_CTX *bn_ctx = NULL;

  k = BN_new();
  bn_ctx = BN_CTX_new();
  if (!k || !bn_ctx) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_BN_LIB);
      goto end;
  }

  do {
       if (!BN_rand_range(k, key->n)) {
         // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_BN_LIB);
         goto end;
       }
     }
  while (BN_is_zero(k));

  if (!key->n_squared) {
      if (!(key->n_squared = BN_new())) {
        // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_MALLOC_FAILURE);
        goto end;
      }
      if (!BN_sqr(key->n_squared, key->n, bn_ctx)) {
        // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_BN_LIB);
        goto end;
      }
  }

  if (!BN_mod_exp(k, k, key->n, key->n_squared, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_BN_LIB);
      goto end;
  }

  if (!BN_mod_mul(r, a, b, key->n_squared, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_BN_LIB);
      goto end;
  }

  if (!BN_mod_mul(r, r, k, key->n_squared, bn_ctx)) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_ADD, ERR_R_BN_LIB);
      goto end;
  }

  ret = 1;
end:
  BN_clear_free(k);
  BN_CTX_free(bn_ctx);
  return ret;
}

int Paillier::PAILLIER_ciphertext_scalar_mul(BIGNUM * r, const BIGNUM * scalar, const BIGNUM * a, PAILLIER * key) {
  int ret = 0;
  BIGNUM *k = NULL;
  BN_CTX *bn_ctx = NULL;

  k = BN_new();
  bn_ctx = BN_CTX_new();
  if (!k || !bn_ctx) {
      // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL, ERR_R_BN_LIB);
      goto end;
  }

  do {
       if (!BN_rand_range(k, key->n)) {
         // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL, ERR_R_BN_LIB);
         goto end;
       }
     }
  while (BN_is_zero(k));

  if (!key->n_squared) {
      if (!(key->n_squared = BN_new())) {
        // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL,
        // ERR_R_MALLOC_FAILURE);
        goto end;
      }
      if (!BN_sqr(key->n_squared, key->n, bn_ctx)) {
        // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL,
        // ERR_R_BN_LIB);
        goto end;
      }
  }

  if (!BN_mod_exp(k, k, key->n, key->n_squared, bn_ctx)) {
     // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL, ERR_R_BN_LIB);
     goto end;
  }

  if (!BN_mod_exp(r, a, scalar, key->n_squared, bn_ctx)) {
     // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL, ERR_R_BN_LIB);
     goto end;
  }

  if (!BN_mod_mul(r, r, k, key->n_squared, bn_ctx)) {
     // PAILLIERerr(PAILLIER_F_PAILLIER_CIPHERTEXT_SCALAR_MUL, ERR_R_BN_LIB);
     goto end;
  }

  ret = 1;
end:
  BN_clear_free(k);
  BN_CTX_free(bn_ctx);
  return ret;
}

int Paillier::PAILLIER_up_ref(PAILLIER * r) {
  int i;

  if (CRYPTO_atomic_add(&r->references, 1, &i, r->lock) <= 0)
    return 0;

  // REF_PRINT_COUNT("PAILLIER", r);
  // REF_ASSERT_ISNT(i < 2);
  return ((i > 1) ? 1 : 0);
}
