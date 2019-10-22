#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <endian.h>

#include "include/bloomfilter.h"
#include "FIPS202-opt64/KeccakHash.h"
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
    for (unsigned int i = 0; i < hashCount; i++) {
        Keccak_HashInstance shake;
        Keccak_HashInitialize_SHAKE256(&shake);

        unsigned int ile = htole32(i);
        Keccak_HashUpdate(&shake, (const uint8_t*) &ile, sizeof(ile) * 8);
        Keccak_HashUpdate(&shake, input, inputLen * 8);
        Keccak_HashFinal(&shake, NULL);

        uint64_t pos = 0;
        Keccak_HashSqueeze(&shake, (uint8_t*) &pos, sizeof(pos) * 8);
        pos = le64toh(pos);

        positions[i] = pos % filterSize;
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
        contains &= bitset_get(filter.bitSet, bitPositions[i]);
    }

    return contains;
}

void bloomfilter_clean(bloomfilter_t *filter) {
    bitset_clean(&filter->bitSet);
}
