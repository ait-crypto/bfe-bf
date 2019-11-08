#ifndef BFE_BITSET_H
#define BFE_BITSET_H

#include "macros.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BITSET_WORD_BITS (8 * sizeof(uint64_t))
#define BITSET_SIZE(size) (((size) + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS)

typedef struct {
  uint64_t* bits;
  unsigned int size;
} bitset_t;

/**
 * Creates a bitset with the given number of bits.
 *
 * @param size                      - the number of bits.
 * @return The initialized bitset with all bits set to FALSE.
 */
static inline bitset_t bitset_init(unsigned int size) {
  bitset_t bitset;
  bitset.bits = calloc(BITSET_SIZE(size), sizeof(uint64_t));
  bitset.size = size;

  return bitset;
}

/**
 * Sets a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit supposed to be set to TRUE.
 */
static inline void bitset_set(bitset_t* bitset, unsigned int index) {
  bitset->bits[index / BITSET_WORD_BITS] |= (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Retrieves a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit in question.
 * @return 0 if the bit is FALSE, non-0 if the bit is TRUE.
 */
static inline uint64_t bitset_get(const bitset_t* bitset, unsigned int index) {
  return bitset->bits[index / BITSET_WORD_BITS] & (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Sets all bits of a bitset to FALSE.
 *
 * @param bitset                    - the corresponding bitset.
 */
static inline void bitset_reset(bitset_t* bitset) {
  memset(bitset->bits, 0, BITSET_SIZE(bitset->size) * sizeof(uint64_t));
}

/**
 * Frees the memory allocated by the bitset. This method has to be called after the bitset is no
 * longer needed to avoid memory leaks.
 *
 * @param bitset                    - the corresponding bitset.
 */
static inline void bitset_clean(bitset_t* bitset) {
  if (bitset) {
    free(bitset->bits);
    bitset->bits = NULL;
    bitset->size = 0;
  }
}

#endif // BFE_BITSET_H
