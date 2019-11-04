#include "include/bfibe.h"

#include "FIPS202-opt64/SimpleFIPS202.h"
#include "include/err_codes.h"
#include "logger.h"
#include "util.h"
#include <relic/relic.h>
#include <stddef.h>
#include <stdio.h>

int bf_ibe_setup_pair(bf_ibe_keys_t* keys) {
  int status = BFE_SUCCESS;

  ep_null(keys->public_key.key);
  bn_null(keys->secret_key.key);

  TRY {
    ep_new(keys->public_key.key);
    bn_new(keys->secret_key.key);

    status = bf_ibe_setup(&keys->secret_key, &keys->public_key);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in IBE setup function.");
    status = BFE_ERR_GENERAL;
  }

  return status;
}

int bf_ibe_setup(bf_ibe_secret_key_t* secret_key, bf_ibe_public_key_t* public_key) {
  int status = BFE_SUCCESS;

  bn_t group1Order;
  bn_null(group1Order);
  TRY {
    bn_new(group1Order);
    ep_curve_get_ord(group1Order);

    bn_rand_mod(secret_key->key, group1Order);
    ep_mul_gen(public_key->key, secret_key->key);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in IBE setup function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(group1Order);
  }

  return status;
}

void bf_ibe_free_keys(bf_ibe_keys_t* keys) {
  if (keys) {
    bn_free(keys->secret_key.key);
    ep_free(keys->public_key.key);
  }
}

int bf_ibe_extract(bf_ibe_extracted_key_t* privateKey, const bf_ibe_secret_key_t* masterKey,
                   const uint8_t* id, size_t idLen) {
  int status = BFE_SUCCESS;
  ep2_t qid;

  ep2_null(qid);
  TRY {
    ep2_new(qid);
    ep2_map(qid, id, idLen);
    ep2_mul(privateKey->key, qid, masterKey->key);
    privateKey->set = 1;
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in IBE extract function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep2_free(qid);
  };

  return status;
}

int bf_ibe_encrypt(bf_ibe_ciphertext_t* ciphertext, const bf_ibe_public_key_t* publicKey,
                   const uint8_t* id, size_t idLen, const uint8_t* message, bn_t r) {
  int status = BFE_SUCCESS;
  uint8_t digest[ciphertext->vLen];
  ep_t publicKeyR;
  ep2_t qid;
  fp12_t gIDR;
  bn_t group1Order;
  ep_t ciphertextLeft;

  ep_null(publicKeyR);
  ep2_null(qid);
  fp12_null(gIDR);
  ep_null(ciphertextLeft);
  ep_null(ciphertext->u);

  TRY {
    ep_new(publicKeyR);
    ep2_new(qid);
    fp12_new(gIDR);
    bn_new(group1Order);
    ep_new(ciphertextLeft);
    ep_new(ciphertext->u);

    ep_mul_gen(ciphertextLeft, r);
    ep_mul(publicKeyR, publicKey->key, r);

    ep2_map(qid, id, idLen);
    pp_map_k12(gIDR, publicKeyR, qid);

    int binSize = fp12_size_bin(gIDR, 0);
    uint8_t bin[binSize];
    fp12_write_bin(bin, binSize, gIDR, 0);
    SHAKE256(digest, ciphertext->vLen, bin, binSize);
    byteArraysXOR(ciphertext->v, digest, message, ciphertext->vLen, ciphertext->vLen);
    ep_copy(ciphertext->u, ciphertextLeft);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in IBE encrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep2_free(qid);
    fp12_free(gIDR);
    bn_free(group1Order);
    ep_free(ciphertextLeft);
    ep_free(publicKeyR);
  };

  return status;
}

int bf_ibe_decrypt(uint8_t* message, const bf_ibe_ciphertext_t* ciphertext,
                   const bf_ibe_extracted_key_t* privateKey) {
  int status = BFE_SUCCESS;
  uint8_t digest[ciphertext->vLen];
  fp12_t dU;
  ep_t p1;
  ep2_t p2;

  fp12_null(dU);
  ep_null(p1);
  ep2_null(p2);

  TRY {
    fp12_new(dU);
    ep_new(p1);
    ep2_new(p2);

    ep_copy(p1, ciphertext->u);
    ep2_copy(p2, privateKey->key);

    pp_map_k12(dU, p1, p2);
    const unsigned int binSize = fp12_size_bin(dU, 0);
    uint8_t bin[binSize];
    fp12_write_bin(bin, binSize, dU, 0);
    md_map(digest, bin, binSize);
    SHAKE256(digest, ciphertext->vLen, bin, binSize);
    byteArraysXOR(message, digest, ciphertext->v, ciphertext->vLen, ciphertext->vLen);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in IBE decrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep2_free(p2);
    ep_free(p1);
    fp12_free(dU);
  };

  return status;
}

bf_ibe_ciphertext_t* bf_ibe_init_ciphertext(size_t messageLen) {
  bf_ibe_ciphertext_t* ciphertext =
      malloc(offsetof(bf_ibe_ciphertext_t, v) + messageLen * sizeof(ciphertext->v[0]));
  ep_null(ciphertext->u);
  ciphertext->vLen = messageLen;
  return ciphertext;
}

void bf_ibe_free_ciphertext(bf_ibe_ciphertext_t* ciphertext) {
  if (ciphertext) {
    ep_free(ciphertext->u);
    free(ciphertext);
  }
}

int bf_ibe_init_secret_key(bf_ibe_secret_key_t* key) {
  int status = BFE_SUCCESS;

  bn_null(key->key);
  TRY {
    bn_new(key->key);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

/**
 * Clear extract key.
 *
 * @param key the key to clear
 */
void bf_ibe_clear_secret_key(bf_ibe_secret_key_t* key) {
  if (key) {
    bn_free(key->key);
    bn_null(key->key);
  }
}

/**
 * Initializes public key.
 *
 * @param key the key to initialize
 */
int bf_ibe_init_public_key(bf_ibe_public_key_t* key) {
  int status = BFE_SUCCESS;

  ep_null(key->key);
  TRY {
    ep_new(key->key);
    ep_set_infty(key->key);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

void bf_ibe_clear_public_key(bf_ibe_public_key_t* key) {
  if (key) {
    ep_free(key->key);
    ep_null(key->key);
  }
}

int bf_ibe_init_extracted_key(bf_ibe_extracted_key_t* key) {
  int status = BFE_SUCCESS;

  ep2_null(key->key);
  key->set = 0;
  TRY {
    ep2_new(key->key);
    ep2_set_infty(key->key);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

void bf_ibe_clear_extracted_key(bf_ibe_extracted_key_t* key) {
  if (key) {
    ep2_set_infty(key->key);
    ep2_free(key->key);
    ep2_null(key->key);
    key->set = 0;
  }
}

__attribute__((constructor)) void coreInit(void) {
  if (core_init() != RLC_OK) {
    core_clean();
  }
  ep_param_set_any_pairf();
}

__attribute__((destructor)) void coreClean(void) {
  core_clean();
}
