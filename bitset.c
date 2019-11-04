#include "include/bitset.h"

#include <stdlib.h>
#include <string.h>

bitset_t bitset_init(unsigned int size) {
  bitset_t bitSet;
  bitSet.bitArray = calloc((size + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS, sizeof(unsigned int));
  bitSet.size     = size;

  return bitSet;
}

void bitset_reset(bitset_t* bitSet) {
  memset(bitSet->bitArray, 0,
         (bitSet->size + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS * sizeof(unsigned int));
}

void bitset_clean(bitset_t* bitset) {
  if (bitset) {
    free(bitset->bitArray);
    bitset->bitArray = NULL;
    bitset->size     = 0;
  }
}
