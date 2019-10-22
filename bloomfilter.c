#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "include/bloomfilter.h"
#include "murmurhash3.h"
#include "logger.h"

bloomfilter_t bloomfilter_init_fixed(int size, int hashCount) {
    bloomfilter_t bloomFilter;

    bloomFilter.bitSet.size = size;
    bloomFilter.hashCount = hashCount;
    bloomFilter.bitSet = bitset_init(bloomFilter.bitSet.size);

    logger_log(LOGGER_INFO, "Instantiated Bloom Filter");
    return bloomFilter;
}

bloomfilter_t bloomfilter_init(int n, double falsePositiveProbability) {
    bloomfilter_t bloomFilter;

    bloomFilter.bitSet.size = bloomfilter_get_needed_size(n, falsePositiveProbability);
    bloomFilter.hashCount = (int) round((bloomFilter.bitSet.size / (double) n) * log(2));
    bloomFilter.bitSet = bitset_init(bloomFilter.bitSet.size);

    logger_log(LOGGER_INFO, "Instantiated Bloom Filter");
    return bloomFilter;
}

int bloomfilter_get_size(bloomfilter_t filter) {
    return filter.bitSet.size;
}

int bloomfilter_get_needed_size(int n, double falsePositiveProbability) {
    return (int) - floor((n * log(falsePositiveProbability)) / pow(log(2), 2));
}

void bloomfilter_get_bit_positions(int *positions, const void *input, int inputLen, int hashCount, int filterSize) {
    uint32_t digest1[1];
    uint32_t digest2[1];
    for (int i = 0; i < hashCount; i++) {
        MurmurHash3_x86_32(input, inputLen, BITSET_HASH_SEED_1, digest1);
        MurmurHash3_x86_32(input, inputLen, BITSET_HASH_SEED_2, digest2);
        positions[i] = abs(digest1[0] + i * digest2[0]) % filterSize;
    }
}

void bloomfilter_add(bloomfilter_t *filter, const void *input, int inputLen) {
    int bitPositions[filter->hashCount];
    bloomfilter_get_bit_positions(bitPositions, input, inputLen, filter->hashCount, filter->bitSet.size);

    for (int i = 0; i < filter->hashCount; i++) {
        bitset_set(&filter->bitSet, bitPositions[i]);
    }
}

void bloomfilter_reset(bloomfilter_t *filter) {
    bitset_reset(&filter->bitSet);
}

int bloomfilter_maybe_contains(bloomfilter_t filter, const void *input, int inputLen) {
    int bitPositions[filter.hashCount];
    bloomfilter_get_bit_positions(bitPositions, input, inputLen, filter.hashCount, filter.bitSet.size);
    int contains = 1;

    for (int i = 0; i < filter.hashCount; i++) {
        contains *= bitset_get(filter.bitSet, bitPositions[i]);
    }

    return contains;
}

void bloomfilter_clean(bloomfilter_t *filter) {
    bitset_clean(&filter->bitSet);
}
