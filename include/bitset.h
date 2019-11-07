#ifndef BFE_BITSET_H
#define BFE_BITSET_H

#include "macros.h"

#include <stdint.h>

#define BITSET_WORD_BITS (8 * sizeof(uint64_t))
#define BITSET_SIZE(size) (((size) + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS)

typedef struct {
  uint64_t* bitArray;
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
  bitset->bitArray[index / BITSET_WORD_BITS] |= (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Retrieves a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit in question.
 * @return 0 if the bit is FALSE, non-0 if the bit is TRUE.
 */
static inline uint64_t bitset_get(bitset_t bitSet, unsigned int index) {
  return bitSet.bitArray[index / BITSET_WORD_BITS] &
         (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
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

#endif // BFE_BITSET_H
