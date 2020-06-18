#ifndef BFE_TYPES_H
#define BFE_TYPES_H

#include <stdint.h>

#include <relic/relic.h>

typedef struct {
  uint64_t* bits;
  unsigned int size;
} bitset_t;

typedef struct _bloomfilter_t {
  unsigned int hash_count;
  bitset_t bitset;
} bloomfilter_t;

#endif
