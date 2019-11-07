#include "include/bloomfilter_enc.h"

#include "FIPS202-opt64/SimpleFIPS202.h"
#include "FIPS202-opt64/KeccakHash.h"

#include "include/bloomfilter.h"
#include "include/err_codes.h"
#include "logger.h"
#include "util.h"

static int bf_ibe_setup(bn_t secret_key, bloomfilter_enc_public_key_t* public_key) {
  int status = BFE_SUCCESS;

  bn_t order;
  bn_null(order);
  TRY {
    bn_new(order);
    ep_curve_get_ord(order);

    bn_rand_mod(secret_key, order);
    ep_mul_gen(public_key->public_key, secret_key);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(order);
  }

  return status;
}

static int bf_ibe_extract(ep2_t extracted_key, const bn_t secret_key,
                   const uint8_t* id, size_t idLen) {
  int status = BFE_SUCCESS;

  ep2_t qid;
  ep2_null(qid);
  TRY {
    ep2_new(qid);
    ep2_map(qid, id, idLen);
    ep2_mul(extracted_key, qid, secret_key);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep2_free(qid);
  }
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

static int bf_ibe_encrypt(uint8_t* dst, ep_t pkr, const uint8_t* id,
                          size_t id_len, const uint8_t* message, size_t message_len) {
  int status = BFE_SUCCESS;
  ep2_t qid;
  fp12_t t;

  ep2_null(qid);
  fp12_null(t);

  TRY {
    ep2_new(qid);
    fp12_new(g);

    // G(i_j)
    ep2_map(qid, id, id_len);
    // e(pk^r, G(i_j))
    pp_map_k12(t, pkr, qid);

    hash_and_xor(dst, message_len, message, t);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    fp12_free(t);
    ep2_free(qid);
  };

  return status;
}

static int bf_ibe_decrypt(uint8_t* message, ep_t g1r, const uint8_t* Kxored, size_t length,
                   ep2_t secret_key) {
  int status = BFE_SUCCESS;
  fp12_t t;
  fp12_null(t);

  TRY {
    fp12_new(t);
    pp_map_k12(t, g1r, secret_key);

    hash_and_xor(message, length, Kxored, t);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    fp12_free(t);
  };

  return status;
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

int bloomfilter_enc_init_secret_key(bloomfilter_enc_secret_key_t* secret_key) {
  memset(secret_key, 0, sizeof(bloomfilter_enc_secret_key_t));
  return BFE_SUCCESS;
}

void bloomfilter_enc_clear_secret_key(bloomfilter_enc_secret_key_t* secret_key) {
  if (secret_key) {
    if (secret_key->secret_keys) {
      for (unsigned int i = 0; i < secret_key->secret_keys_len; i++) {
        if (bitset_get(secret_key->filter.bitSet, i) == 0) {
          ep2_set_infty(secret_key->secret_keys[i]);
          ep2_free(secret_key->secret_keys[i]);
        }
      }
      free(secret_key->secret_keys);
      secret_key->secret_keys_len = 0;
      secret_key->secret_keys     = NULL;
    }
    bloomfilter_clean(&secret_key->filter);
  }
}

int bloomfilter_enc_init_public_key(bloomfilter_enc_public_key_t* public_key) {
  public_key->filterHashCount = public_key->filterSize = public_key->keyLength = 0;

  int status = BFE_SUCCESS;
  ep_null(public_key->public_key);
  TRY {
    ep_new(public_key->public_key);
  } CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

void bloomfilter_enc_clear_public_key(bloomfilter_enc_public_key_t* public_key) {
  if (public_key) {
    public_key->filterHashCount = public_key->filterSize = public_key->keyLength = 0;

    ep_free(public_key->public_key);
    ep_null(public_key->public_key);
  }
}

int bloomfilter_enc_setup(bloomfilter_enc_public_key_t* public_key,
                          bloomfilter_enc_secret_key_t* secret_key, unsigned int keyLength,
                          unsigned int filterElementNumber, double falsePositiveProbability) {
  int status = BFE_SUCCESS;
  bn_t sk;
  bn_null(sk);

  bloomfilter_t filter         = bloomfilter_init(filterElementNumber, falsePositiveProbability);
  const unsigned int bloomSize = bloomfilter_get_size(&filter);

  secret_key->secret_keys = calloc(bloomSize, sizeof(ep2_t));
  if (!secret_key->secret_keys) {
    status = BFE_ERR_GENERAL;
    goto end;
  }

  public_key->keyLength       = keyLength;
  public_key->filterSize      = bloomSize;
  public_key->filterHashCount = filter.hashCount;
  secret_key->secret_keys_len = bloomSize;
  secret_key->filter          = filter;

  TRY {
    bn_new(sk);

    status = bf_ibe_setup(sk, public_key);
    if (!status) {
      #pragma omp parallel for reduction(| : status)
      for (unsigned int i = 0; i < bloomSize; i++) {
        const uint32_t id = htole32(i);
        status |= bf_ibe_extract(secret_key->secret_keys[i], sk, (const uint8_t*)&id, sizeof(id));
      }
    }
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(sk);
  }

end:
  return status;
}

static int _bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t* ciphertextPair,
                                    bloomfilter_enc_public_key_t* public_key, bn_t r,
                                    const uint8_t* K) {
  int status = BFE_SUCCESS;
  unsigned int bitPositions[public_key->filterHashCount];
  memcpy(ciphertextPair->K, K, ciphertextPair->KLen);

  ep_t pkr;
  ep_null(pkr);

  TRY {
    // g_1^r
    ep_mul_gen(ciphertextPair->ciphertext.u, r);
    // pk^r
    ep_new(pkr);
    ep_mul(pkr, public_key->public_key, r);

    bloomfilter_get_bit_positions(bitPositions, ciphertextPair->ciphertext.u, public_key->filterHashCount,
                                  public_key->filterSize);

    for (unsigned int i = 0; i < public_key->filterHashCount; i++) {
      status = bf_ibe_encrypt(&ciphertextPair->ciphertext.v[i * public_key->keyLength], pkr, (const uint8_t*)&bitPositions[i], sizeof(i), K, ciphertextPair->KLen);
      if (status) {
        break;
      }
    }
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption encrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep_free(pkr);
  }

  return status;
}

int bloomfilter_enc_encrypt_key(bloomfilter_enc_ciphertext_pair_t* ciphertextPair,
                                bloomfilter_enc_public_key_t* public_key, const uint8_t* K) {
  int status = BFE_SUCCESS;
  bn_t order;
  bn_t r;

  bn_null(order);
  bn_null(r);

  TRY {
    bn_new(order);
    bn_new(r);

    ep_curve_get_ord(order);

    unsigned int exponentLength  = bn_size_bin(order);
    unsigned int totalRandLength = public_key->keyLength + exponentLength;
    uint8_t randDigest[totalRandLength];
    SHAKE256(randDigest, totalRandLength, K, public_key->keyLength);
    bn_read_bin(r, randDigest, exponentLength);

    status = _bloomfilter_enc_encrypt(ciphertextPair, public_key, r, K);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption encrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(order);
    bn_free(r);
  }

  return status;
}

int bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t* ciphertextPair,
                            bloomfilter_enc_public_key_t* public_key) {
  uint8_t K[public_key->keyLength];
  generateRandomBytes(K, public_key->keyLength);

  return bloomfilter_enc_encrypt_key(ciphertextPair, public_key, K);
}

void bloomfilter_enc_puncture(bloomfilter_enc_secret_key_t* secret_key,
                              bloomfilter_enc_ciphertext_t* ciphertext) {
  unsigned int affectedIndexes[secret_key->filter.hashCount];

  bloomfilter_add(&secret_key->filter, ciphertext->u);
  bloomfilter_get_bit_positions(affectedIndexes, ciphertext->u, secret_key->filter.hashCount,
                                bloomfilter_get_size(&secret_key->filter));
  for (unsigned int i = 0; i < secret_key->filter.hashCount; i++) {
    ep2_set_infty(secret_key->secret_keys[affectedIndexes[i]]);
    ep2_free(secret_key->secret_keys[affectedIndexes[i]]);
  }
}

int bloomfilter_enc_ciphertext_cmp(const bloomfilter_enc_ciphertext_t* ciphertext1,
                                   const bloomfilter_enc_ciphertext_t* ciphertext2) {
  return (ep_cmp(ciphertext1->u, ciphertext2->u) == RLC_EQ &&
          ciphertext1->vLen == ciphertext2->vLen &&
          memcmp(ciphertext1->v, ciphertext2->v, ciphertext1->vLen) == 0)
             ? 0
             : 1;
}

int bloomfilter_enc_decrypt(uint8_t* key, bloomfilter_enc_public_key_t* public_key,
                            bloomfilter_enc_secret_key_t* secretKey,
                            bloomfilter_enc_ciphertext_t* ciphertext) {
  int status = BFE_SUCCESS;

  uint8_t tempKey[public_key->keyLength];
  unsigned int affectedIndexes[secretKey->filter.hashCount];

  bloomfilter_get_bit_positions(affectedIndexes, ciphertext->u, secretKey->filter.hashCount,
                                bloomfilter_get_size(&secretKey->filter));

  status = BFE_ERR_GENERAL;
  for (unsigned int i = 0; i < secretKey->filter.hashCount; i++) {
    if (bitset_get(secretKey->filter.bitSet, affectedIndexes[i]) == 0) {
      status = bf_ibe_decrypt(tempKey, ciphertext->u, &ciphertext->v[i * public_key->keyLength],
                              public_key->keyLength, secretKey->secret_keys[affectedIndexes[i]]);
      if (status == BFE_SUCCESS) {
        break;
      }
    }
  }

  if (status != BFE_SUCCESS) {
    logger_log(LOGGER_DEBUG, "Key already punctured");
    return BFE_ERR_KEY_PUNCTURED;
  }

  bloomfilter_enc_ciphertext_pair_t genCiphertextPair;
  bloomfilter_enc_init_ciphertext_pair(&genCiphertextPair, public_key);

  bn_t r, group1Order;
  bn_null(r);
  bn_null(group1Order);

  TRY {
    bn_new(r);
    bn_new(group1Order);

    ep_curve_get_ord(group1Order);
    unsigned int exponentLength  = bn_size_bin(group1Order);
    unsigned int totalRandLength = public_key->keyLength + exponentLength;
    uint8_t randDigest[totalRandLength];
    SHAKE256(randDigest, totalRandLength, tempKey, public_key->keyLength);
    bn_read_bin(r, randDigest, exponentLength);

    status = _bloomfilter_enc_encrypt(&genCiphertextPair, public_key, r, tempKey);

    if (!status && bloomfilter_enc_ciphertext_cmp(&genCiphertextPair.ciphertext, ciphertext) == 0) {
      memcpy(key, tempKey, public_key->keyLength);
    } else {
      logger_log(LOGGER_INFO, "Encryption failed or ciphertexts did not match");
    }
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption decrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(r);
    bn_free(group1Order);
    bloomfilter_enc_clear_ciphertext_pair(&genCiphertextPair);
  }

  return status;
}

static int init_ciphertext(bloomfilter_enc_ciphertext_t* ciphertext, unsigned int hash_count,
                           unsigned int key_length) {
  int status = BFE_SUCCESS;

  ep_null(ciphertext->u);
  TRY {
    ep_new(ciphertext->u);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  if (!status) {
    ciphertext->vLen = hash_count * key_length;
    ciphertext->v    = calloc(hash_count, key_length);
    if (!ciphertext->v) {
      status = BFE_ERR_GENERAL;
    }
  }

  return status;
}

int bloomfilter_enc_init_ciphertext(bloomfilter_enc_ciphertext_t* ciphertext,
                                    const bloomfilter_enc_public_key_t* public_key) {
  return init_ciphertext(ciphertext, public_key->filterHashCount, public_key->keyLength);
}

void bloomfilter_enc_clear_ciphertext(bloomfilter_enc_ciphertext_t* ciphertext) {
  if (ciphertext) {
    ep_free(ciphertext->u);
    ciphertext->vLen = 0;
    free(ciphertext->v);
    ciphertext->v = NULL;
  }
}

int bloomfilter_enc_init_ciphertext_pair(bloomfilter_enc_ciphertext_pair_t* pair,
                                         const bloomfilter_enc_public_key_t* public_key) {
  pair->KLen = public_key->keyLength;
  pair->K    = calloc(sizeof(uint8_t), public_key->keyLength);
  if (!pair->K) {
    return BFE_ERR_GENERAL;
  }

  return bloomfilter_enc_init_ciphertext(&pair->ciphertext, public_key);
}

void bloomfilter_enc_clear_ciphertext_pair(bloomfilter_enc_ciphertext_pair_t* ciphertextPair) {
  if (ciphertextPair) {
    bloomfilter_enc_clear_ciphertext(&ciphertextPair->ciphertext);
    ciphertextPair->KLen = 0;
    free(ciphertextPair->K);
    ciphertextPair->K = NULL;
  }
}

unsigned int bloomfilter_enc_ciphertext_size_bin(const bloomfilter_enc_ciphertext_t* ciphertext) {
  return 2 * sizeof(uint32_t) + ep_size_bin(ciphertext->u, 0) + ciphertext->vLen;
}

void bloomfilter_enc_ciphertext_write_bin(uint8_t* bin, bloomfilter_enc_ciphertext_t* ciphertext) {
  const uint32_t uLen     = ep_size_bin(ciphertext->u, 0);
  const uint32_t totalLen = bloomfilter_enc_ciphertext_size_bin(ciphertext);

  write_u32(&bin, totalLen);
  write_u32(&bin, uLen);

  ep_write_bin(bin, ep_size_bin(ciphertext->u, 0), ciphertext->u, 0);
  memcpy(&bin[uLen], ciphertext->v, ciphertext->vLen);
}

int bloomfilter_enc_ciphertext_read_bin(bloomfilter_enc_ciphertext_t* ciphertext, const uint8_t* bin) {
  const uint32_t totalLen = read_u32(&bin);
  const uint32_t uLen     = read_u32(&bin);
  const unsigned int vLen = totalLen - uLen - 2 * sizeof(uint32_t);

  if (init_ciphertext(ciphertext, 1, vLen)) {
    logger_log(LOGGER_ERROR, "Failed to init ciphertext");
    return BFE_ERR_GENERAL;
  }

  int status = BFE_SUCCESS;
  TRY {
    ep_read_bin(ciphertext->u, bin, uLen);
    ciphertext->vLen = vLen;
    memcpy(ciphertext->v, &bin[uLen], vLen);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in bloomfilter_enc_ciphertext_read_bin function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {}

  return status;
}

unsigned int bloomfilter_enc_public_key_size_bin(const bloomfilter_enc_public_key_t* public_key) {
  return 4 * sizeof(uint32_t) + ep_size_bin(public_key->public_key, 0);
}

void bloomfilter_enc_public_key_write_bin(uint8_t* bin, bloomfilter_enc_public_key_t* public_key) {
  const unsigned int keyLen     = ep_size_bin(public_key->public_key, 0);

  write_u32(&bin, public_key->filterHashCount);
  write_u32(&bin, public_key->filterSize);
  write_u32(&bin, public_key->keyLength);
  write_u32(&bin, keyLen);
  ep_write_bin(bin, keyLen, public_key->public_key, 0);
}

int bloomfilter_enc_public_key_read_bin(bloomfilter_enc_public_key_t* public_key, const uint8_t* bin) {
  public_key->filterHashCount = read_u32(&bin);
  public_key->filterSize      = read_u32(&bin);
  public_key->keyLength       = read_u32(&bin);

  const unsigned int keyLen = read_u32(&bin);

  int status = BFE_SUCCESS;
  TRY {
    ep_read_bin(public_key->public_key, bin, keyLen);
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in bloomfilter_enc_public_key_read_bin function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {}

  return status;
}

unsigned int bloomfilter_enc_secret_key_size_bin(const bloomfilter_enc_secret_key_t* secret_key) {
  unsigned int num_keys = 0;
  for (unsigned int i = 0; i < secret_key->filter.bitSet.size; i++) {
    if (bitset_get(secret_key->filter.bitSet, i) == 0) {
      ++num_keys;
    }
  }

  return 3 * sizeof(uint32_t) + BITSET_SIZE(secret_key->filter.bitSet.size) * sizeof(uint64_t) + num_keys * ep2_size_bin(secret_key->secret_keys[0], 0);
}

void bloomfilter_enc_secret_key_write_bin(uint8_t* bin, bloomfilter_enc_secret_key_t* secret_key) {
  write_u32(&bin, secret_key->filter.hashCount);
  write_u32(&bin, secret_key->filter.bitSet.size);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->filter.bitSet.size); ++i) {
    write_u64(&bin, secret_key->filter.bitSet.bitArray[i]);
  }

  const unsigned int secret_key_len = ep2_size_bin(secret_key->secret_keys[0], 0);
  write_u32(&bin, secret_key_len);
  for (unsigned int i = 0; i < secret_key->filter.bitSet.size; i++) {
    if (bitset_get(secret_key->filter.bitSet, i) == 0) {
      ep2_write_bin(bin, secret_key_len, secret_key->secret_keys[i], 0);
      bin += secret_key_len;
    }
  }
}

int bloomfilter_enc_secret_key_read_bin(bloomfilter_enc_secret_key_t* secret_key, const uint8_t* bin) {
  const unsigned int hash_count = read_u32(&bin);
  const unsigned int filter_size = read_u32(&bin);

  secret_key->filter = bloomfilter_init_fixed(filter_size, hash_count);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->filter.bitSet.size); ++i) {
    secret_key->filter.bitSet.bitArray[i] = read_u64(&bin);
  }
  secret_key->secret_keys_len = filter_size;
  secret_key->secret_keys = calloc(filter_size, sizeof(ep2_t));

  int status = BFE_SUCCESS;
  const unsigned int secret_key_len = read_u32(&bin);
  TRY {
    for (unsigned int i = 0; i < filter_size; i++) {
      if (bitset_get(secret_key->filter.bitSet, i) == 0) {
        // ep2_null(secret_key->secret_keys[i]);
        ep2_new(secret_key->secret_keys[i]);
        ep2_read_bin(secret_key->secret_keys[i], bin, secret_key_len);
        bin += secret_key_len;
      }
    }
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in bloomfilter_enc_secret_key_read_bin function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {}

  return status;
}
