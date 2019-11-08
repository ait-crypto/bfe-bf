#ifndef BFE_UTIL_H
#define BFE_UTIL_H

#include <endian.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void random_bytes(uint8_t* bin, unsigned int size);

static inline void write_u32(uint8_t** dst, uint32_t v) {
  v = htole32(v);
  memcpy(*dst, &v, sizeof(v));
  *dst += sizeof(v);
}

static inline uint32_t read_u32(const uint8_t** src) {
  uint32_t v;
  memcpy(&v, *src, sizeof(v));
  *src += sizeof(v);
  return le32toh(v);
}

static inline void write_u64(uint8_t** dst, uint64_t v) {
  v = htole64(v);
  memcpy(*dst, &v, sizeof(v));
  *dst += sizeof(v);
}

static inline uint64_t read_u64(const uint8_t** src) {
  uint64_t v;
  memcpy(&v, *src, sizeof(v));
  *src += sizeof(v);
  return le64toh(v);
}

#endif // BFE_UTIL_H
