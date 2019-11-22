#ifndef BFE_TYPES_H
#define BFE_TYPES_H

#include <stdint.h>

#include <relic/relic.h>

typedef struct {
  uint64_t* bits;
  unsigned int size;
} bitset_t;

typedef struct _bloomfilter_t {
  unsigned int hash_count;
  bitset_t bitset;
} bloomfilter_t;

/**
 * BFE PKEM public key
 */
typedef struct {
  unsigned int filter_hash_count; /**< number of hash functions used in the bloom filter */
  unsigned int filter_size;       /**< size of the bloom filter */
  unsigned int key_size;          /**< size of encapuslated keys */

  ep_t public_key; /**< the public key of the Boneh-Franklin IBE */
} bfe_public_key_t;

/**
 * BFE PKEM secret key
 */
typedef struct {
  bloomfilter_t filter;         /**< the bloom filter */
  unsigned int secret_keys_len; /**< size of @ref secret_keys */
  ep2_t* secret_keys;           /**< all available secret keys */
} bfe_secret_key_t;

/**
 * BFE PKEM ciphertext
 */
typedef struct {
  ep_t u;
  unsigned int v_size;
  uint8_t* v;
} bfe_ciphertext_t;

#endif
