#include "util.h"

#include <endian.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <relic/relic.h>

#include "logger.h"

#if defined __GLIBC__ && defined __linux__
#if __GLIBC__ > 2 || __GLIBC_MINOR__ > 24
#include <errno.h>
#include <sys/random.h>

void generateRandomBytes(uint8_t* dst, unsigned int binSize) {
  const int ret = getrandom(dst, binSize, GRND_NONBLOCK);
  if (ret == -1) {
    logger_log(LOGGER_ERROR, "Failed to get random data: %d", errno);
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
