#include "include/bfe.h"

#include "FIPS202-opt64/KeccakHash.h"
#include "include/bloomfilter.h"
#include "include/err_codes.h"
#include "util.h"

#define EP_SIZE (1 + 2 * RLC_FP_BYTES)
#define EP2_SIZE (1 + 4 * RLC_FP_BYTES)
#define FP12_SIZE (12 * RLC_FP_BYTES)

static int bf_ibe_setup(bn_t secret_key, bfe_public_key_t* public_key) {
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

static int bf_ibe_extract(ep2_t extracted_key, const bn_t secret_key, const uint8_t* id,
                          size_t id_size) {
  int status = BFE_SUCCESS;

  ep2_t qid;
  ep2_null(qid);
  TRY {
    ep2_new(qid);
    ep2_map(qid, id, id_size);
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
  static const uint8_t domain[] = "BFE_G";

  uint8_t bin[FP12_SIZE]  = {0};
  fp12_write_bin(bin, FP12_SIZE, y, 0);

  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE256(&shake);
  Keccak_HashUpdate(&shake, domain, sizeof(domain) * 8);
  Keccak_HashUpdate(&shake, bin, FP12_SIZE * 8);
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

static int bf_ibe_encrypt(uint8_t* dst, ep_t pkr, const uint8_t* id, size_t id_len,
                          const uint8_t* message, size_t message_len) {
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

int bfe_init_secret_key(bfe_secret_key_t* secret_key) {
  memset(secret_key, 0, sizeof(bfe_secret_key_t));
  return BFE_SUCCESS;
}

void bfe_clear_secret_key(bfe_secret_key_t* secret_key) {
  if (secret_key) {
    if (secret_key->secret_keys) {
      for (unsigned int i = 0; i < secret_key->secret_keys_len; i++) {
        if (bitset_get(&secret_key->filter.bitset, i) == 0) {
          ep2_set_infty(secret_key->secret_keys[i]);
          ep2_free(secret_key->secret_keys[i]);
        }
      }
      free(secret_key->secret_keys);
      secret_key->secret_keys_len = 0;
      secret_key->secret_keys     = NULL;
    }
    bloomfilter_clear(&secret_key->filter);
  }
}

int bfe_init_public_key(bfe_public_key_t* public_key) {
  public_key->filter_hash_count = public_key->filter_size = public_key->key_size = 0;

  int status = BFE_SUCCESS;
  ep_null(public_key->public_key);
  TRY {
    ep_new(public_key->public_key);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

void bfe_clear_public_key(bfe_public_key_t* public_key) {
  if (public_key) {
    public_key->filter_hash_count = public_key->filter_size = public_key->key_size = 0;

    ep_free(public_key->public_key);
    ep_null(public_key->public_key);
  }
}

int bfe_setup(bfe_public_key_t* public_key, bfe_secret_key_t* secret_key, unsigned int key_size,
              unsigned int filterElementNumber, double falsePositiveProbability) {
  int status = BFE_SUCCESS;

  bloomfilter_t filter         = bloomfilter_init(filterElementNumber, falsePositiveProbability);
  const unsigned int bloomSize = bloomfilter_get_size(&filter);

  secret_key->secret_keys = calloc(bloomSize, sizeof(ep2_t));
  if (!secret_key->secret_keys) {
    bloomfilter_clear(&filter);
    return BFE_ERR_GENERAL;
  }

  public_key->key_size          = key_size;
  public_key->filter_size       = bloomSize;
  public_key->filter_hash_count = filter.hash_count;
  secret_key->secret_keys_len   = bloomSize;
  secret_key->filter            = filter;

  bn_t sk;
  bn_null(sk);
  TRY {
    bn_new(sk);

    /* generate IBE key */
    status = bf_ibe_setup(sk, public_key);
    if (!status) {
#pragma omp parallel for reduction(| : status)
      for (unsigned int i = 0; i < bloomSize; i++) {
        /* extraxt key for identity i */
        const uint64_t id = htole64(i);
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

  return status;
}

static int internal_encrypt(bfe_ciphertext_t* ciphertext, const bfe_public_key_t* public_key,
                            bn_t r, const uint8_t* K) {
  int status = BFE_SUCCESS;
  unsigned int bitPositions[public_key->filter_hash_count];

  ep_t pkr;
  ep_null(pkr);

  TRY {
    // g_1^r
    ep_mul_gen(ciphertext->u, r);
    // pk^r
    ep_new(pkr);
    ep_mul(pkr, public_key->public_key, r);

    bloomfilter_get_bit_positions(bitPositions, ciphertext->u, public_key->filter_hash_count,
                                  public_key->filter_size);

    for (unsigned int i = 0; i < public_key->filter_hash_count; i++) {
      /* extraxt key for identity bitPositions[i] */
      const uint64_t id = htole64(bitPositions[i]);

      status = bf_ibe_encrypt(&ciphertext->v[i * public_key->key_size], pkr,
                              (const uint8_t*)&id, sizeof(id), K, public_key->key_size);
      if (status) {
        break;
      }
    }
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    ep_free(pkr);
  }

  return status;
}

int bfe_encrypt(bfe_ciphertext_t* ciphertext, uint8_t* Kout, const bfe_public_key_t* public_key) {
  uint8_t K[public_key->key_size];
  random_bytes(K, public_key->key_size);

  int status = BFE_SUCCESS;
  bn_t r;
  bn_null(r);

  TRY {
    bn_new(r);

    ep_curve_get_ord(r);
    const unsigned int exponentLength = bn_size_bin(r);

    Keccak_HashInstance shake;
    Keccak_HashInitialize_SHAKE256(&shake);
    Keccak_HashUpdate(&shake, K, public_key->key_size * 8);
    Keccak_HashFinal(&shake, NULL);

    // r of (r, K') = R(K)
    uint8_t buf[exponentLength];
    Keccak_HashSqueeze(&shake, buf, exponentLength * 8);
    bn_read_bin(r, buf, exponentLength);

    status = internal_encrypt(ciphertext, public_key, r, K);
    if (status == BFE_SUCCESS) {
      // K' of (r, K') = R(K)
      Keccak_HashSqueeze(&shake, Kout, public_key->key_size * 8);
    }
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(r);
  }

  return status;
}

void bfe_puncture(bfe_secret_key_t* secret_key, bfe_ciphertext_t* ciphertext) {
  unsigned int indices[secret_key->filter.hash_count];

  bloomfilter_add(&secret_key->filter, ciphertext->u);
  bloomfilter_get_bit_positions(indices, ciphertext->u, secret_key->filter.hash_count,
                                bloomfilter_get_size(&secret_key->filter));
  for (unsigned int i = 0; i < secret_key->filter.hash_count; i++) {
    ep2_set_infty(secret_key->secret_keys[indices[i]]);
    ep2_free(secret_key->secret_keys[indices[i]]);
  }
}

static int bfe_ciphertext_cmp(const bfe_ciphertext_t* ciphertext1,
                              const bfe_ciphertext_t* ciphertext2) {
  return (ep_cmp(ciphertext1->u, ciphertext2->u) == RLC_EQ &&
          ciphertext1->v_size == ciphertext2->v_size &&
          memcmp(ciphertext1->v, ciphertext2->v, ciphertext1->v_size) == 0)
             ? 0
             : 1;
}

int bfe_decrypt(uint8_t* key, bfe_public_key_t* public_key, bfe_secret_key_t* secretKey,
                bfe_ciphertext_t* ciphertext) {
  int status = BFE_SUCCESS;

  uint8_t key_buf[public_key->key_size];
  unsigned int indices[secretKey->filter.hash_count];

  bloomfilter_get_bit_positions(indices, ciphertext->u, secretKey->filter.hash_count,
                                bloomfilter_get_size(&secretKey->filter));

  status = BFE_ERR_GENERAL;
  for (unsigned int i = 0; i < secretKey->filter.hash_count; i++) {
    if (bitset_get(&secretKey->filter.bitset, indices[i]) == 0) {
      status = bf_ibe_decrypt(key_buf, ciphertext->u, &ciphertext->v[i * public_key->key_size],
                              public_key->key_size, secretKey->secret_keys[indices[i]]);
      if (status == BFE_SUCCESS) {
        break;
      }
    }
  }

  if (status != BFE_SUCCESS) {
    return BFE_ERR_KEY_PUNCTURED;
  }

  bfe_ciphertext_t check_ciphertext;
  bfe_init_ciphertext(&check_ciphertext, public_key);

  bn_t r;
  bn_null(r);

  TRY {
    bn_new(r);

    ep_curve_get_ord(r);
    const unsigned int exponentLength = bn_size_bin(r);

    Keccak_HashInstance shake;
    Keccak_HashInitialize_SHAKE256(&shake);
    Keccak_HashUpdate(&shake, key_buf, public_key->key_size * 8);
    Keccak_HashFinal(&shake, NULL);

    // r of (r, K') = R(K)
    uint8_t buf[exponentLength];
    Keccak_HashSqueeze(&shake, buf, exponentLength * 8);
    bn_read_bin(r, buf, exponentLength);

    status = internal_encrypt(&check_ciphertext, public_key, r, key_buf);

    if (!status && bfe_ciphertext_cmp(&check_ciphertext, ciphertext) == 0) {
      // K' of (r, K') = R(K)
      Keccak_HashSqueeze(&shake, key, public_key->key_size * 8);
    } else {
      status = BFE_ERR_GENERAL;
    }
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }
  FINALLY {
    bn_free(r);
    bfe_clear_ciphertext(&check_ciphertext);
  }

  return status;
}

static int init_ciphertext(bfe_ciphertext_t* ciphertext, unsigned int hash_count,
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
    ciphertext->v_size = hash_count * key_length;
    ciphertext->v      = calloc(hash_count, key_length);
    if (!ciphertext->v) {
      status = BFE_ERR_GENERAL;
    }
  }

  return status;
}

int bfe_init_ciphertext(bfe_ciphertext_t* ciphertext, const bfe_public_key_t* public_key) {
  return init_ciphertext(ciphertext, public_key->filter_hash_count, public_key->key_size);
}

void bfe_clear_ciphertext(bfe_ciphertext_t* ciphertext) {
  if (ciphertext) {
    free(ciphertext->v);
    ep_free(ciphertext->u);
    ciphertext->v_size = 0;
    ciphertext->v      = NULL;
  }
}

unsigned int bfe_ciphertext_size_bin(const bfe_ciphertext_t* ciphertext) {
  return 1 * sizeof(uint32_t) + EP_SIZE + ciphertext->v_size;
}

void bfe_ciphertext_write_bin(uint8_t* bin, bfe_ciphertext_t* ciphertext) {
  const uint32_t u_size     = EP_SIZE;
  const uint32_t total_size = bfe_ciphertext_size_bin(ciphertext);

  write_u32(&bin, total_size);

  ep_write_bin(bin, EP_SIZE, ciphertext->u, 0);
  memcpy(&bin[u_size], ciphertext->v, ciphertext->v_size);
}

int bfe_ciphertext_read_bin(bfe_ciphertext_t* ciphertext, const uint8_t* bin) {
  const uint32_t total_size = read_u32(&bin);
  const unsigned int v_size = total_size - EP_SIZE - 1 * sizeof(uint32_t);

  if (init_ciphertext(ciphertext, 1, v_size)) {
    return BFE_ERR_GENERAL;
  }

  int status = BFE_SUCCESS;
  TRY {
    ep_read_bin(ciphertext->u, bin, EP_SIZE);
    ciphertext->v_size = v_size;
    memcpy(ciphertext->v, &bin[EP_SIZE], v_size);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

unsigned int bfe_public_key_size_bin(void) {
  return 3 * sizeof(uint32_t) + EP_SIZE;
}

void bfe_public_key_write_bin(uint8_t* bin, bfe_public_key_t* public_key) {

  write_u32(&bin, public_key->filter_hash_count);
  write_u32(&bin, public_key->filter_size);
  write_u32(&bin, public_key->key_size);
  ep_write_bin(bin, EP_SIZE, public_key->public_key, 0);
}

int bfe_public_key_read_bin(bfe_public_key_t* public_key, const uint8_t* bin) {
  public_key->filter_hash_count = read_u32(&bin);
  public_key->filter_size       = read_u32(&bin);
  public_key->key_size          = read_u32(&bin);

  int status = BFE_SUCCESS;
  TRY {
    ep_read_bin(public_key->public_key, bin, EP_SIZE);
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}

unsigned int bfe_secret_key_size_bin(const bfe_secret_key_t* secret_key) {
  unsigned int num_keys = 0;
  for (unsigned int i = 0; i < secret_key->filter.bitset.size; i++) {
    if (bitset_get(&secret_key->filter.bitset, i) == 0) {
      ++num_keys;
    }
  }

  return 2 * sizeof(uint32_t) + BITSET_SIZE(secret_key->filter.bitset.size) * sizeof(uint64_t) +
         num_keys * EP2_SIZE;
}

void bfe_secret_key_write_bin(uint8_t* bin, bfe_secret_key_t* secret_key) {
  write_u32(&bin, secret_key->filter.hash_count);
  write_u32(&bin, secret_key->filter.bitset.size);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->filter.bitset.size); ++i) {
    write_u64(&bin, secret_key->filter.bitset.bits[i]);
  }

  for (unsigned int i = 0; i < secret_key->filter.bitset.size; i++) {
    if (bitset_get(&secret_key->filter.bitset, i) == 0) {
      ep2_write_bin(bin, EP2_SIZE, secret_key->secret_keys[i], 0);
      bin += EP2_SIZE;
    }
  }
}

int bfe_secret_key_read_bin(bfe_secret_key_t* secret_key, const uint8_t* bin) {
  const unsigned int hash_count  = read_u32(&bin);
  const unsigned int filter_size = read_u32(&bin);

  secret_key->filter = bloomfilter_init_fixed(filter_size, hash_count);
  for (unsigned int i = 0; i < BITSET_SIZE(secret_key->filter.bitset.size); ++i) {
    secret_key->filter.bitset.bits[i] = read_u64(&bin);
  }
  secret_key->secret_keys_len = filter_size;
  secret_key->secret_keys     = calloc(filter_size, sizeof(ep2_t));

  int status = BFE_SUCCESS;
  TRY {
    for (unsigned int i = 0; i < filter_size; i++) {
      if (bitset_get(&secret_key->filter.bitset, i) == 0) {
        ep2_new(secret_key->secret_keys[i]);
        ep2_read_bin(secret_key->secret_keys[i], bin, EP2_SIZE);
        bin += EP2_SIZE;
      }
    }
  }
  CATCH_ANY {
    status = BFE_ERR_GENERAL;
  }

  return status;
}
