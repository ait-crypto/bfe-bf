#include <endian.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "FIPS202-opt64/KeccakHash.h"
#include "bitset.h"
#include "bloomfilter.h"

static const double log_2 = log(2);
static const double log_22 = log(2) * log(2);

static unsigned int get_needed_size(unsigned int n, double false_positive_prob) {
  return -floor((n * log(false_positive_prob)) / log_22);
}

bloomfilter_t bf_init_fixed(unsigned int size, unsigned int hash_count) {
  return (bloomfilter_t){.hash_count = hash_count, .bitset = bitset_init(size)};
}

bloomfilter_t bf_init(unsigned int n, double false_positive_prob) {
  const unsigned int bitset_size = get_needed_size(n, false_positive_prob);

  return (bloomfilter_t){.hash_count = ceil((bitset_size / (double)n) * log_2),
                         .bitset     = bitset_init(bitset_size)};
}

unsigned int bf_get_size(const bloomfilter_t* filter) {
  return filter->bitset.size;
}

static unsigned int get_position(uint32_t hash_idx, const uint8_t* input, size_t input_len,
                                 unsigned int filter_size) {
  static const uint8_t domain[] = "BF_HASH";

  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE128(&shake);

  Keccak_HashUpdate(&shake, domain, sizeof(domain) * 8);
  hash_idx = htole32(hash_idx);
  Keccak_HashUpdate(&shake, (const uint8_t*)&hash_idx, sizeof(hash_idx) * 8);
  Keccak_HashUpdate(&shake, input, input_len * 8);
  Keccak_HashFinal(&shake, NULL);

  uint64_t output = 0;
  Keccak_HashSqueeze(&shake, (uint8_t*)&output, sizeof(output) * 8);
  return le64toh(output) % filter_size;
}

void bf_get_bit_positions(unsigned int* positions, const ep_t input, unsigned int hash_count,
                          unsigned int filter_size) {
  const unsigned int buffer_size       = ep_size_bin(input, 0);
  uint8_t buffer[2 * RLC_FP_BYTES + 1] = {0};
  ep_write_bin(buffer, buffer_size, input, 0);

  for (unsigned int i = 0; i < hash_count; ++i) {
    positions[i] = get_position(i, buffer, buffer_size, filter_size);
  }
}

void bf_add(bloomfilter_t* filter, const ep_t input) {
  const unsigned int bloomfilter_size  = bf_get_size(filter);
  const unsigned int buffer_size       = ep_size_bin(input, 0);
  uint8_t buffer[2 * RLC_FP_BYTES + 1] = {0};
  ep_write_bin(buffer, buffer_size, input, 0);

  for (unsigned int i = 0; i < filter->hash_count; ++i) {
    unsigned int pos = get_position(i, buffer, buffer_size, bloomfilter_size);
    bitset_set(&filter->bitset, pos);
  }
}

int bf_maybe_contains(const bloomfilter_t* filter, const ep_t input) {
  const unsigned int bloomfilter_size  = bf_get_size(filter);
  const unsigned int buffer_size       = ep_size_bin(input, 0);
  uint8_t buffer[2 * RLC_FP_BYTES + 1] = {0};
  ep_write_bin(buffer, buffer_size, input, 0);

  for (unsigned int i = 0; i < filter->hash_count; ++i) {
    unsigned int pos = get_position(i, buffer, buffer_size, bloomfilter_size);
    if (!bitset_get(&filter->bitset, pos)) {
      return 0;
    }
  }

  return 1;
}

void bf_clear(bloomfilter_t* filter) {
  bitset_clean(&filter->bitset);
}
