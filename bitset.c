#include <stdlib.h>
#include "include/bitset.h"

bitset_t bitset_init(int size) {
    bitset_t bitSet;
    bitSet.size = size;
    bitSet.bitArray = calloc((size + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS, sizeof(unsigned int));

    return bitSet;
}

void bitset_set(bitset_t *bitset, int index) {
    bitset->bitArray[index / BITSET_WORD_BITS] |= (1 << (index & (BITSET_WORD_BITS - 1)));
}

int bitset_get(bitset_t bitSet, int index) {
    unsigned int importantBit = bitSet.bitArray[index / BITSET_WORD_BITS] & (1 << (index & (BITSET_WORD_BITS - 1)));
    if (importantBit > 0) {
        return 1;
    }
    return 0;
}

void bitset_reset(bitset_t *bitSet) {
    for (int i = 0; i < (bitSet->size + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS; i++) {
        bitSet->bitArray[i] = 0;
    }
}

void bitset_clean(bitset_t *bitset) {
    free(bitset->bitArray);
}