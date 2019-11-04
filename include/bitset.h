#ifndef BFE_BITSET_H
#define BFE_BITSET_H

#include "macros.h"

#define BITSET_WORD_BITS (8 * sizeof(unsigned int))

typedef struct {
  unsigned int* bitArray;
  unsigned int size;
} bitset_t;

/**
 * Creates a bitset with the given number of bits.
 *
 * @param size                      - the number of bits.
 * @return The initialized bitset with all bits set to FALSE.
 */
BFE_VISIBLE bitset_t bitset_init(unsigned int size);

/**
 * Sets a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit supposed to be set to TRUE.
 */
static inline void bitset_set(bitset_t* bitset, unsigned int index) {
  bitset->bitArray[index / BITSET_WORD_BITS] |= (1 << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Retrieves a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit in question.
 * @return 0 if the bit is FALSE, non-0 if the bit is TRUE.
 */
static inline int bitset_get(bitset_t bitSet, unsigned int index) {
  return bitSet.bitArray[index / BITSET_WORD_BITS] & (1 << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Sets all bits of a bitset to FALSE.
 *
 * @param bitset                    - the corresponding bitset.
 */
BFE_VISIBLE void bitset_reset(bitset_t* bitSet);

/**
 * Frees the memory allocated by the bitset. This method has to be called after the bitset is no
 * longer needed to avoid memory leaks.
 *
 * @param bitset                    - the corresponding bitset.
 */
BFE_VISIBLE void bitset_clean(bitset_t* bitset);

#endif // MASTER_PROJECT_BITSET_H
