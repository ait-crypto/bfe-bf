/*
 *  This file is part of the BFE library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#include "include/crypto_api.h"
#include "include/bfe.h"

#include <string.h>

int crypto_kem_keypair(unsigned char* serialized_pk, unsigned char* serialized_sk) {
  bfe_secret_key_t sk;
  bfe_public_key_t pk;

  // generate new keys
  bfe_init_secret_key(&sk);
  bfe_init_public_key(&pk);
  int status = bfe_keygen(&pk, &sk, CRYPTO_BYTES, 1 << 19, 0.0009765625);

  if (!status) {
    bfe_public_key_write_bin(serialized_pk, &pk);
    memcpy(serialized_sk, serialized_pk, CRYPTO_PUBLICKEYBYTES);
    bfe_secret_key_write_bin(serialized_sk + CRYPTO_PUBLICKEYBYTES, &sk);
  }

  bfe_clear_secret_key(&sk);
  bfe_clear_public_key(&pk);

  return status;
}

int crypto_kem_enc(unsigned char* serialized_ct, unsigned char* k,
                   const unsigned char* serialized_pk) {
  bfe_public_key_t pk;
  // deserialize the public key
  int status = bfe_public_key_read_bin(&pk, serialized_pk);
  if (status) {
    return status;
  }

  // encaps a new key
  bfe_ciphertext_t ciphertext;
  bfe_init_ciphertext(&ciphertext, &pk);
  status = bfe_encaps(&ciphertext, k, &pk);
  if (status) {
    goto ret;
  }

  // serialize the ciphertext
  bfe_ciphertext_write_bin(serialized_ct, &ciphertext);

ret:
  // clean up
  bfe_clear_ciphertext(&ciphertext);
  bfe_clear_public_key(&pk);

  return status;
}

int crypto_kem_dec(unsigned char* k, const unsigned char* serialized_ct,
                   const unsigned char* serialized_sk) {
  bfe_public_key_t pk;
  // deserialize the public key
  int status = bfe_public_key_read_bin(&pk, serialized_sk);
  if (status) {
    return status;
  }

  // deserialize the secret key
  bfe_secret_key_t sk;
  status = bfe_secret_key_read_bin(&sk, serialized_sk + CRYPTO_PUBLICKEYBYTES);
  if (status) {
    goto ret;
  }

  // deserialize the ciphertext
  bfe_ciphertext_t ct;
  status = bfe_ciphertext_read_bin(&ct, serialized_ct);
  if (status) {
    goto ret;
  }

  // decaps ciphertext
  status = bfe_decaps(k, &pk, &sk, &ct);

ret:
  bfe_clear_ciphertext(&ct);
  bfe_clear_secret_key(&sk);
  bfe_clear_public_key(&pk);

  return status;
}

int crypto_kem_punc(unsigned char* serialized_sk, const unsigned char* serialized_ct) {
  // deserialize the secret key
  bfe_secret_key_t sk;
  int status = bfe_secret_key_read_bin(&sk, serialized_sk + CRYPTO_PUBLICKEYBYTES);
  if (status) {
    return status;
  }

  // deserialize the ciphertext
  bfe_ciphertext_t ciphertext;
  status = bfe_ciphertext_read_bin(&ciphertext, serialized_ct);
  if (status) {
    goto ret;
  }

  // puncture secret key and serialized it again
  bfe_puncture(&sk, &ciphertext);
  bfe_secret_key_write_bin(serialized_sk + CRYPTO_PUBLICKEYBYTES, &sk);

ret:
  // clean up
  bfe_clear_ciphertext(&ciphertext);
  bfe_clear_secret_key(&sk);

  return status;
}
