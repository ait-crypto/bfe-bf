/*
 *  This file is part of the BFE library.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the CC0 license, see LICENSE for more details.
 *  SPDX-License-Identifier: CC0-1.0
 */

#ifndef BFE_BITSET_H
#define BFE_BITSET_H

#include "include/macros.h"
#include "include/types.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BITSET_WORD_BITS (8 * sizeof(uint64_t))
#define BITSET_SIZE(size) (((size) + BITSET_WORD_BITS - 1) / BITSET_WORD_BITS)

/**
 * Creates a bitset with the given number of bits.
 *
 * @param size the number of bits.
 * @return The initialized bitset with all bits set to 0.
 */
static inline bitset_t bitset_init(unsigned int size) {
  return (bitset_t){.bits = calloc(BITSET_SIZE(size), sizeof(uint64_t)), .size = size};
}

/**
 * Sets a specific bit of a bitset.
 *
 * @param bitset the gbitset.
 * @param index  the index of the bit supposed to be set to 1.
 */
static inline void bitset_set(bitset_t* bitset, unsigned int index) {
  bitset->bits[index / BITSET_WORD_BITS] |= (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Retrieves a specific bit of a bitset.
 *
 * @param bitset the bitset.
 * @param index  the index of the bit in question.
 * @return return non-0 if the bit is set, 0 otherwise
 */
static inline uint64_t bitset_get(const bitset_t* bitset, unsigned int index) {
  return bitset->bits[index / BITSET_WORD_BITS] & (UINT64_C(1) << (index & (BITSET_WORD_BITS - 1)));
}

/**
 * Frees the memory allocated by the bitset.
 *
 * @param bitset the bitset.
 */
static inline void bitset_clean(bitset_t* bitset) {
  if (bitset) {
    free(bitset->bits);
    bitset->bits = NULL;
    bitset->size = 0;
  }
}

#endif // BFE_BITSET_H
