#ifndef MASTER_PROJECT_BLOOMFILTER_H
#define MASTER_PROJECT_BLOOMFILTER_H

#include "bitset.h"

typedef struct _bloomfilter_t {
    unsigned int hashCount;
    bitset_t bitSet;
} bloomfilter_t;

/**
 * Calculates a size of a bloom filter needed to satisfy the given expected number of elements inside the filter
 * with the target false positive probability. No bloom filter is created, this function is made for estimation purposes.
 *
 * @param n                         - the expected number of elements inside the filter.
 * @param falsePositiveProbability  - target false positive probability for the filter with the specified number of elements.
 * @return The size a bloom filter with the given parameters would have.
 */
unsigned int bloomfilter_get_needed_size(unsigned int n, double falsePositiveProbability);

/**
 * Creates a new bloom filter with the explicit size and hash count parameters.
 *
 * @param size                      - the number of bits in the filter.
 * @param hashCount                 - number of hash functions to be used.
 * @return The initialized bloom filter.
 */
bloomfilter_t bloomfilter_init_fixed(unsigned int size, unsigned int hashCount);

/**
 * Creates a new bloom filter with the given parameters.
 *
 * @param n                         - the expected number of elements inside the filter.
 * @param falsePositiveProbability  - target false positive probability for the filter with the specified number of elements.
 * @return The initialized bloom filter.
 */
bloomfilter_t bloomfilter_init(unsigned int n, double falsePositiveProbability);

/**
 * Returns the total number of positions inside the filter.
 *
 * @param filter                    - the corresponding filter.
 * @return The size of the filter.
 */
unsigned int bloomfilter_get_size(bloomfilter_t filter);

/**
 * Returns the bit positions of the bloom filter that would be set for the given input. No bloom filter instance is
 * needed, this function is made for estimation purposes.
 *
 * @param positions[out]            - the returned array. The length of the array has to be equal to hashCount.
 * @param input[in]                 - input element for the filter.
 * @param inputLen[in]              - length of input in bytes.
 * @param hashCount[in]             - number of hash function in the hypothetical bloom filter.
 * @param filterSize[in]            - size of the hypothetical bloom filter.
 * @return The size of the filter.
 */
void bloomfilter_get_bit_positions(unsigned int *positions, const void *input, size_t inputLen, unsigned int hashCount, unsigned int filterSize);

/**
 * Adds a given element to the bloom filter.
 *
 * @param filter                    - the filter to which the element is being added.
 * @param input                     - input element for the filter.
 * @param inputLen                  - length of input in bytes.
 */
void bloomfilter_add(bloomfilter_t *filter, const void *input, size_t inputLen);

/**
 * Sets all the bits of a bloom filter to FALSE.
 *
 * @param filter                    - the filter to reset.
 */
void bloomfilter_reset(bloomfilter_t *filter);

/**
 * Checks whether the given element is possibly in the filter. Due to possibility of false positives only the false
 * cases are considered to be 100% accurate.
 *
 * @param filter                    - the corresponding filter.
 * @param input                     - input element for the filter.
 * @param inputLen                  - length of input in bytes.
 * @return 0 if element is definitely not in the filter, 1 if element is likely in the filter.
 */
int bloomfilter_maybe_contains(bloomfilter_t filter, const void *input, size_t inputLen);

/**
 * Frees the memory allocated by the bloom filter. This method has to be called after the filter is no longer needed to
 * avoid memory leaks.
 *
 * @param filter                    - the corresponding filter.
 */
void bloomfilter_clean(bloomfilter_t *filter);

#endif //MASTER_PROJECT_BLOOMFILTER_H
