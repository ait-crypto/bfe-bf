#include "include/bitset.h"

#include <stdlib.h>
#include <string.h>

bitset_t bitset_init(unsigned int size) {
  bitset_t bitSet;
  bitSet.bitArray = calloc(BITSET_SIZE(size), sizeof(uint64_t));
  bitSet.size     = size;

  return bitSet;
}

void bitset_reset(bitset_t* bitSet) {
  memset(bitSet->bitArray, 0, BITSET_SIZE(bitSet->size) * sizeof(uint64_t));
}

void bitset_clean(bitset_t* bitset) {
  if (bitset) {
    free(bitset->bitArray);
    bitset->bitArray = NULL;
    bitset->size     = 0;
  }
}
