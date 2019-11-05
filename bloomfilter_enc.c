#include "include/bloomfilter_enc.h"

#include "FIPS202-opt64/SimpleFIPS202.h"
#include "include/bfibe.h"
#include "include/bloomfilter.h"
#include "include/err_codes.h"
#include "logger.h"
#include "util.h"

#include <stddef.h>

int bloomfilter_enc_init_secret_key(bloomfilter_enc_secret_key_t* secret_key) {
  memset(secret_key, 0, sizeof(bloomfilter_enc_secret_key_t));
  return BFE_SUCCESS;
}

void bloomfilter_enc_clear_secret_key(bloomfilter_enc_secret_key_t* secret_key) {
  if (secret_key) {
    if (secret_key->secretKey) {
      for (unsigned int i = 0; i < secret_key->secretKeyLen; i++) {
        bf_ibe_clear_extracted_key(&secret_key->secretKey[i]);
      }
      free(secret_key->secretKey);
      secret_key->secretKey = NULL;
    }
    bloomfilter_clean(&secret_key->filter);
  }
}

int bloomfilter_enc_init_public_key(bloomfilter_enc_public_key_t* public_key) {
  public_key->filterHashCount = public_key->filterSize = public_key->keyLength = 0;

  return bf_ibe_init_public_key(&public_key->publicKey);
}

void bloomfilter_enc_clear_public_key(bloomfilter_enc_public_key_t* public_key) {
  if (public_key) {
    public_key->filterHashCount = public_key->filterSize = public_key->keyLength = 0;

    bf_ibe_clear_public_key(&public_key->publicKey);
  }
}

int bloomfilter_enc_setup(bloomfilter_enc_public_key_t* public_key,
                          bloomfilter_enc_secret_key_t* secret_key, unsigned int keyLength,
                          unsigned int filterElementNumber, double falsePositiveProbability) {
  bf_ibe_secret_key_t sk;
  int status = bf_ibe_init_secret_key(&sk);
  if (status) {
    return BFE_ERR_GENERAL;
  }

  status = bf_ibe_setup(&sk, &public_key->publicKey);
  if (status) {
    goto end;
  }

  bloomfilter_t filter         = bloomfilter_init(filterElementNumber, falsePositiveProbability);
  const unsigned int bloomSize = bloomfilter_get_size(filter);

  secret_key->secretKey = calloc(bloomSize, sizeof(bf_ibe_extracted_key_t));
  if (!secret_key->secretKey) {
    status = BFE_ERR_GENERAL;
    goto end;
  }

  public_key->keyLength                = keyLength;
  public_key->filterSize               = bloomSize;
  public_key->filterHashCount          = filter.hashCount;
  secret_key->secretKeyLen             = bloomSize;
  secret_key->filter                   = filter;

  #pragma omp parallel for reduction(|:status)
  for (unsigned int i = 0; i < bloomSize; i++) {
    const uint32_t id = htole32(i);
    status |= bf_ibe_extract(&secret_key->secretKey[i], &sk, (const uint8_t*) &id, sizeof(id));
  }

end:
  bf_ibe_clear_secret_key(&sk);
  return status;
}

static int _bloomfilter_enc_encrypt(bloomfilter_enc_ciphertext_pair_t* ciphertextPair,
                                    bloomfilter_enc_public_key_t* public_key, bn_t r,
                                    const uint8_t* K) {
  int status = BFE_SUCCESS;
  unsigned int bitPositions[public_key->filterHashCount];
  memcpy(ciphertextPair->K, K, ciphertextPair->KLen);

  ep_t gR;
  ep_null(gR);

  bf_ibe_ciphertext_t* tempCiphertext = NULL;

  TRY {
    ep_new(gR);
    ep_mul_gen(gR, r);

    tempCiphertext = bf_ibe_init_ciphertext(ciphertextPair->KLen);

    unsigned int binLen = ep_size_bin(gR, 0);
    uint8_t bin[binLen];
    ep_write_bin(bin, binLen, gR, 0);
    bloomfilter_get_bit_positions(bitPositions, bin, binLen, public_key->filterHashCount,
                                  public_key->filterSize);

    for (unsigned int i = 0; i < public_key->filterHashCount; i++) {
      status = bf_ibe_encrypt(tempCiphertext, &public_key->publicKey,
                              (const uint8_t*)&bitPositions[i], sizeof(i), K, r);
      if (status) {
        break;
      }
      memcpy(&ciphertextPair->ciphertext.v[i * public_key->keyLength], tempCiphertext->v,
             tempCiphertext->vLen);
      if (i == 0) {
        ep_copy(ciphertextPair->ciphertext.u, tempCiphertext->u);
      }
    }
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption encrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bf_ibe_free_ciphertext(tempCiphertext);
    ep_free(gR);
  }

  return status;
}

int bloomfilter_enc_encrypt_key(bloomfilter_enc_ciphertext_pair_t* ciphertextPair,
                                bloomfilter_enc_public_key_t* public_key, const uint8_t* K) {
  int status = BFE_SUCCESS;
  bn_t group1Order;
  bn_t r;

  bn_null(group1Order);
  bn_null(r);

  TRY {
    bn_new(group1Order);
    bn_new(r);

    ep_curve_get_ord(group1Order);

    unsigned int exponentLength  = bn_size_bin(group1Order);
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
    bn_free(group1Order);
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

void bloomfilter_enc_puncture(bloomfilter_enc_secret_key_t* secretKey,
                              bloomfilter_enc_ciphertext_t* ciphertext) {
  unsigned int affectedIndexes[secretKey->filter.hashCount];

  unsigned int binLen = ep_size_bin(ciphertext->u, 0);
  uint8_t bin[binLen];
  ep_write_bin(bin, binLen, ciphertext->u, 0);

  bloomfilter_add(&secretKey->filter, bin, binLen);
  bloomfilter_get_bit_positions(affectedIndexes, bin, binLen, secretKey->filter.hashCount,
                                bloomfilter_get_size(secretKey->filter));
  for (unsigned int i = 0; i < secretKey->filter.hashCount; i++) {
    bf_ibe_clear_extracted_key(&secretKey->secretKey[affectedIndexes[i]]);
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

  unsigned int binLen = ep_size_bin(ciphertext->u, 0);
  uint8_t bin[binLen];
  ep_write_bin(bin, binLen, ciphertext->u, 0);

  if (bloomfilter_maybe_contains(secretKey->filter, bin, binLen)) {
    logger_log(LOGGER_WARNING, "Secret key already punctured with the given ciphertext!");
    return BFE_ERR_KEY_PUNCTURED;
  }

  uint8_t tempKey[public_key->keyLength];
  unsigned int affectedIndexes[secretKey->filter.hashCount];
  bf_ibe_ciphertext_t* ibeCiphertext = malloc(offsetof(bf_ibe_ciphertext_t, v) +
                                              public_key->keyLength * sizeof(ibeCiphertext->v[0]));
  ibeCiphertext->vLen                = public_key->keyLength;

  bn_t r, group1Order;
  bloomfilter_enc_ciphertext_pair_t genCiphertextPair;
  bloomfilter_enc_init_ciphertext_pair(&genCiphertextPair, public_key);

  ep_null(ibeCiphertext->u);
  bn_null(r);
  bn_null(group1Order);

  TRY {
    ep_new(ibeCiphertext->u);
    bn_new(r);
    bn_new(group1Order);

    bloomfilter_get_bit_positions(affectedIndexes, bin, binLen, secretKey->filter.hashCount,
                                  bloomfilter_get_size(secretKey->filter));

    status = BFE_ERR_GENERAL;
    for (unsigned int i = 0; i < secretKey->filter.hashCount; i++) {
      if (secretKey->secretKey[affectedIndexes[i]].set) {
        ep_copy(ibeCiphertext->u, ciphertext->u);
        memcpy(ibeCiphertext->v, &ciphertext->v[i * ibeCiphertext->vLen], ibeCiphertext->vLen);
        status = bf_ibe_decrypt(tempKey, ibeCiphertext, &secretKey->secretKey[affectedIndexes[i]]);
        if (status == BFE_SUCCESS) {
          break;
        }
      }
    }

    if (status != BFE_SUCCESS) {
      THROW(ERR_NO_VALID);
    }

    ep_curve_get_ord(group1Order);
    unsigned int exponentLength  = bn_size_bin(group1Order);
    unsigned int totalRandLength = public_key->keyLength + exponentLength;
    uint8_t randDigest[totalRandLength];
    SHAKE256(randDigest, totalRandLength, tempKey, public_key->keyLength);
    bn_read_bin(r, randDigest, exponentLength);

    status = _bloomfilter_enc_encrypt(&genCiphertextPair, public_key, r, tempKey);

    if (!status && bloomfilter_enc_ciphertext_cmp(&genCiphertextPair.ciphertext, ciphertext) == 0) {
      memcpy(key, tempKey, public_key->keyLength);
    }
  }
  CATCH_ANY {
    logger_log(LOGGER_ERROR, "Error occurred in Bloom Filter Encryption decrypt function.");
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(r);
    bn_free(group1Order);
    bf_ibe_free_ciphertext(ibeCiphertext);
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
  return 4 * sizeof(uint32_t) + ep_size_bin(public_key->publicKey.key, 0);
}

void bloomfilter_enc_public_key_write_bin(uint8_t* bin, bloomfilter_enc_public_key_t* public_key) {
  const unsigned int keyLen     = ep_size_bin(public_key->publicKey.key, 0);

  write_u32(&bin, public_key->filterHashCount);
  write_u32(&bin, public_key->filterSize);
  write_u32(&bin, public_key->keyLength);
  write_u32(&bin, keyLen);
  ep_write_bin(bin, keyLen, public_key->publicKey.key, 0);
}

int bloomfilter_enc_public_key_read_bin(bloomfilter_enc_public_key_t* public_key, const uint8_t* bin) {
  public_key->filterHashCount = read_u32(&bin);
  public_key->filterSize      = read_u32(&bin);
  public_key->keyLength       = read_u32(&bin);

  const unsigned int keyLen = read_u32(&bin);

  int status = BFE_SUCCESS;
  ep_null(public_key->publicKey.key);
  TRY {
    ep_new(public_key->publicKey.key);
    ep_read_bin(public_key->publicKey.key, bin, keyLen);
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

  return 3 * sizeof(uint32_t) + BITSET_SIZE(secret_key->filter.bitSet.size) * sizeof(uint64_t) + num_keys * ep2_size_bin(secret_key->secretKey->key, 0);
}

void bloomfilter_enc_secret_key_write_bin(uint8_t* bin, bloomfilter_enc_secret_key_t* secret_key) {
  write_u32(&bin, secret_key->filter.hashCount);
  write_u32(&bin, secret_key->filter.bitSet.size);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->filter.bitSet.size); ++i) {
    write_u64(&bin, secret_key->filter.bitSet.bitArray[i]);
  }

  const unsigned int secret_key_len = ep2_size_bin(secret_key->secretKey->key, 0);
  write_u32(&bin, secret_key_len);
  for (unsigned int i = 0; i < secret_key->filter.bitSet.size; i++) {
    if (bitset_get(secret_key->filter.bitSet, i) == 0) {
      ep2_write_bin(bin, secret_key_len, secret_key->secretKey[i].key, 0);
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
  secret_key->secretKeyLen = filter_size;
  secret_key->secretKey = calloc(filter_size, sizeof(bf_ibe_extracted_key_t));

  int status = BFE_SUCCESS;
  const unsigned int secret_key_len = read_u32(&bin);
  TRY {
    for (unsigned int i = 0; i < filter_size; i++) {
      if (bitset_get(secret_key->filter.bitSet, i) == 0) {
        status |= bf_ibe_init_extracted_key(&secret_key->secretKey[i]);
        ep2_read_bin(secret_key->secretKey[i].key, bin, secret_key_len);
        bin += secret_key_len;
        secret_key->secretKey[i].set = 1;
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
