#include "include/bitset.h"

#include <stdlib.h>
#include <string.h>

bitset_t bitset_init(unsigned int size) {
  bitset_t bitSet;
  bitSet.size     = size;
  bitSet.bitArray = calloc((size + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS, sizeof(unsigned int));

  return bitSet;
}

void bitset_set(bitset_t* bitset, unsigned int index) {
  bitset->bitArray[index / BITSET_WORD_BITS] |= (1 << (index & (BITSET_WORD_BITS - 1)));
}

int bitset_get(bitset_t bitSet, unsigned int index) {
  const unsigned int importantBit =
      bitSet.bitArray[index / BITSET_WORD_BITS] & (1 << (index & (BITSET_WORD_BITS - 1)));
  if (importantBit) {
    return 1;
  }
  return 0;
}

void bitset_reset(bitset_t* bitSet) {
  memset(bitSet->bitArray, 0,
         (bitSet->size + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS * sizeof(unsigned int));
}

void bitset_clean(bitset_t* bitset) {
  if (bitset) {
    free(bitset->bitArray);
    bitset->size     = 0;
    bitset->bitArray = NULL;
  }
}
