#ifndef MASTER_PROJECT_BITSET_H
#define MASTER_PROJECT_BITSET_H

#define BITSET_WORD_BITS (8 * sizeof(unsigned int))

typedef struct _bitset_t {
    int size;
    unsigned int *bitArray;
} bitset_t;

/**
 * Creates a bitset with the given number of bits.
 *
 * @param size                      - the number of bits.
 * @return The initialized bitset with all bits set to FALSE.
 */
bitset_t bitset_init(int size);

/**
 * Sets a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit supposed to be set to TRUE.
 */
void bitset_set(bitset_t *bitset, int index);

/**
 * Retrieves a specific bit of a bitset.
 *
 * @param bitset                    - the corresponding bitset.
 * @param index                     - the index of the bit in question.
 * @return 0 if the bit is FALSE, 1 if the bit is TRUE.
 */
int bitset_get(bitset_t bitSet, int index);

/**
 * Sets all bits of a bitset to FALSE.
 *
 * @param bitset                    - the corresponding bitset.
 */
void bitset_reset(bitset_t *bitSet);

/**
 * Frees the memory allocated by the bitset. This method has to be called after the bitset is no longer needed to avoid
 * memory leaks.
 *
 * @param bitset                    - the corresponding bitset.
 */
void bitset_clean(bitset_t *bitset);

#endif //MASTER_PROJECT_BITSET_H
