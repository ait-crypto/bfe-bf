#include <endian.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "FIPS202-opt64/KeccakHash.h"
#include "include/bloomfilter.h"

bloomfilter_t bloomfilter_init_fixed(unsigned int size, unsigned int hashCount) {
  bloomfilter_t bloomFilter;

  bloomFilter.hashCount = hashCount;
  bloomFilter.bitSet    = bitset_init(size);

  return bloomFilter;
}

bloomfilter_t bloomfilter_init(unsigned int n, double falsePositiveProbability) {
  bloomfilter_t bloomFilter;

  const unsigned int bitset_size = bloomfilter_get_needed_size(n, falsePositiveProbability);
  bloomFilter.hashCount          = ceil((bitset_size / (double)n) * log(2));
  bloomFilter.bitSet             = bitset_init(bitset_size);

  return bloomFilter;
}

unsigned int bloomfilter_get_size(bloomfilter_t* filter) {
  return filter->bitSet.size;
}

unsigned int bloomfilter_get_needed_size(unsigned int n, double falsePositiveProbability) {
  return -floor((n * log(falsePositiveProbability)) / pow(log(2), 2));
}

static unsigned int get_position(uint32_t hash_idx, const uint8_t* input, size_t input_len,
                                 unsigned int filter_size) {
  Keccak_HashInstance shake;
  Keccak_HashInitialize_SHAKE128(&shake);

  hash_idx = htole32(hash_idx);
  Keccak_HashUpdate(&shake, (const uint8_t*)&hash_idx, sizeof(hash_idx) * 8);
  Keccak_HashUpdate(&shake, input, input_len * 8);
  Keccak_HashFinal(&shake, NULL);

  uint64_t pos = 0;
  Keccak_HashSqueeze(&shake, (uint8_t*)&pos, sizeof(pos) * 8);
  pos = le64toh(pos);

  return pos % filter_size;
}

void bloomfilter_get_bit_positions(unsigned int* positions, const ep_t input,
                                   unsigned int hashCount, unsigned int filterSize) {
  const unsigned int bin_size       = ep_size_bin(input, 0);
  uint8_t bin[2 * RLC_FP_BYTES + 1] = {0};
  ep_write_bin(bin, sizeof(bin), input, 0);

  for (unsigned int i = 0; i < hashCount; i++) {
    positions[i] = get_position(i, bin, bin_size, filterSize);
  }
}

void bloomfilter_add(bloomfilter_t* filter, const ep_t input) {
  const unsigned int bloomfilter_size = bloomfilter_get_size(filter);
  const unsigned int bin_size         = ep_size_bin(input, 0);
  uint8_t bin[2 * RLC_FP_BYTES + 1]   = {0};
  ep_write_bin(bin, sizeof(bin), input, 0);

  for (unsigned int i = 0; i < filter->hashCount; i++) {
    unsigned int pos = get_position(i, bin, bin_size, bloomfilter_size);
    bitset_set(&filter->bitSet, pos);
  }
}

void bloomfilter_reset(bloomfilter_t* filter) {
  bitset_reset(&filter->bitSet);
}

int bloomfilter_maybe_contains(bloomfilter_t filter, const ep_t input) {
  const unsigned int bloomfilter_size = bloomfilter_get_size(&filter);
  const unsigned int bin_size         = ep_size_bin(input, 0);
  uint8_t bin[2 * RLC_FP_BYTES + 1]   = {0};
  ep_write_bin(bin, sizeof(bin), input, 0);

  for (unsigned int i = 0; i < filter.hashCount; i++) {
    unsigned int pos = get_position(i, bin, bin_size, bloomfilter_size);
    if (!bitset_get(filter.bitSet, pos)) {
      return 0;
    }
  }

  return 1;
}

void bloomfilter_clean(bloomfilter_t* filter) {
  bitset_clean(&filter->bitSet);
}
