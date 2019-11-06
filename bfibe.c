#include "include/bfibe.h"

#include "FIPS202-opt64/KeccakHash.h"
#include "include/err_codes.h"
#include "logger.h"

#include <relic/relic.h>
#include <stddef.h>
#include <stdio.h>

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

int bf_ibe_extract(bf_ibe_extracted_key_t* privateKey, const bf_ibe_secret_key_t* masterKey,
                   const uint8_t* id, size_t idLen) {
  int status = BFE_SUCCESS;
  ep2_t qid;

  ep2_null(qid);
  TRY {
    ep2_new(qid);
    ep2_map(qid, id, idLen);
    ep2_mul(privateKey->key, qid, masterKey->key);
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

// G(y) \xor K
static void hash_and_xor(uint8_t* dst, size_t len, const uint8_t* input, fp12_t y) {
  const unsigned int size = fp12_size_bin(y, 0);
  uint8_t bin[12 * RLC_FP_BYTES] = { 0 };
  fp12_write_bin(bin, size, y, 0);

  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE256(&shake);
  Keccak_HashUpdate(&shake, bin, size * 8);
  Keccak_HashFinal(&shake, NULL);

  for (; len; len -= MIN(len, 64), dst += 64, input += 64) {
    uint8_t buf[64];
    const size_t l = MIN(len, 64);

    Keccak_HashSqueeze(&shake, buf, l * 8);
    for (size_t i = 0; i < l; ++i) {
      dst[i] = input[i] ^ buf[i];
    }
  }
}

int bf_ibe_encrypt(bf_ibe_ciphertext_t* ciphertext, const bf_ibe_public_key_t* publicKey,
                   const uint8_t* id, size_t idLen, const uint8_t* message, bn_t r) {
  int status = BFE_SUCCESS;
  ep_t publicKeyR;
  ep2_t qid;
  fp12_t gIDR;

  ep_null(publicKeyR);
  ep2_null(qid);
  fp12_null(gIDR);
  ep_null(ciphertextLeft);
  ep_null(ciphertext->u);

  TRY {
    ep_new(publicKeyR);
    ep2_new(qid);
    fp12_new(gIDR);
    ep_new(ciphertext->u);

    // g_1^r
    ep_mul_gen(ciphertext->u, r);
    // pk^r
    ep_mul(publicKeyR, publicKey->key, r);

    // G(i_j)
    ep2_map(qid, id, idLen);
    // e(pk^r, G(i_j))
    pp_map_k12(gIDR, publicKeyR, qid);

    hash_and_xor(ciphertext->v, ciphertext->vLen, message, gIDR);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in IBE encrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep2_free(qid);
    fp12_free(gIDR);
    ep_free(publicKeyR);
  };

  return status;
}

int bf_ibe_decrypt(uint8_t* message, const bf_ibe_ciphertext_t* ciphertext,
                   const bf_ibe_extracted_key_t* privateKey) {
  int status = BFE_SUCCESS;
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

    hash_and_xor(message, ciphertext->vLen, ciphertext->v, dU);
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
  }
}

__attribute__((constructor)) static void init_relic(void) {
  if (core_init() != RLC_OK) {
    core_clean();
  }
  ep_param_set_any_pairf();
}

__attribute__((destructor)) static void clean_relic(void) {
  core_clean();
}
