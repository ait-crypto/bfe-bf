#ifndef BFE_BLOOMFILTER_H
#define BFE_BLOOMFILTER_H

#include "include/types.h"

#include <stddef.h>

/**
 * Creates a new bloom filter with the explicit size and hash count parameters.
 *
 * @param[in] size the number of bits in the filter.
 * @param[in] hash_count number of hash functions to be used.
 * @return The initialized bloom filter.
 */
bloomfilter_t bf_init_fixed(unsigned int size, unsigned int hash_count);

/**
 * Creates a new bloom filter with the given parameters.
 *
 * @param[in] n the expected number of elements inside the filter.
 * @param[in] false_positive_prob target false positive probability for the filter with the
 * specified number of elements.
 * @return The initialized bloom filter.
 */
bloomfilter_t bf_init(unsigned int n, double false_positive_prob);

/**
 * Returns the total number of positions inside the filter.
 *
 * @param[in] filter the corresponding filter.
 * @return The size of the filter.
 */
unsigned int bf_get_size(const bloomfilter_t* filter);

/**
 * Returns the bit positions of the bloom filter that would be set for the given input. No bloom
 * filter instance is needed, this function is made for estimation purposes.
 *
 * @param[out] positions the returned array. The length of the array has to be equal to hash_count.
 * @param[in] input input element for the filter.
 * @param[in] hash_count number of hash function in the hypothetical bloom filter.
 * @param[in] filter_size size of the hypothetical bloom filter.
 * @return The size of the filter.
 */
void bf_get_bit_positions(unsigned int* positions, const ep_t input, unsigned int hash_count,
                          unsigned int filter_size);

/**
 * Adds a given element to the bloom filter.
 *
 * @param[out] filter the filter to which the element is being added.
 * @param[in] input input element for the filter.
 */
void bf_add(bloomfilter_t* filter, const ep_t input);

/**
 * Checks whether the given element is possibly in the filter. Due to possibility of false positives
 * only the false cases are considered to be 100% accurate.
 *
 * @param[in] filter the corresponding filter.
 * @param[in] input input element for the filter.
 * @return 0 if element is definitely not in the filter, 1 if element is likely in the filter.
 */
int bf_maybe_contains(const bloomfilter_t* filter, const ep_t input);

/**
 * Frees the memory allocated by the bloom filter. This method has to be called after the filter is
 * no longer needed to avoid memory leaks.
 *
 * @param[out] filter the filter to clear.
 */
void bf_clear(bloomfilter_t* filter);

#endif // BFE_BLOOMFILTER_H
