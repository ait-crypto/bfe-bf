#include "util.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include <relic/relic.h>

#include "logger.h"

void byteArraysXOR(uint8_t* out, const uint8_t* array1, const uint8_t* array2, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    out[i] = array1[i] ^ array2[i];
  }
}

#if defined __GLIBC__ && defined __linux__
#if __GLIBC__ > 2 || __GLIBC_MINOR__ > 24
#include <sys/random.h>

void generateRandomBytes(uint8_t* dst, unsigned int binSize) {
  const int ret = getrandom(dst, binSize, GRND_NONBLOCK);
  if (ret) {
    logger_log(LOGGER_ERROR, "Failed to get random data: %d", ret);
  }
}
#else /* older glibc */
#include <sys/syscall.h>
#include <unistd.h>

void generateRandomBytes(uint8_t* dst, unsigned int binSize) {
  syscall(SYS_getrandom, dst, binSize, 0);
}
#endif
#endif
