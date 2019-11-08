#include "util.h"

#include "logger.h"

#if defined(__GLIBC__) && defined(__linux__)
#if __GLIBC__ > 2 || __GLIBC_MINOR__ > 24
#include <errno.h>
#include <sys/random.h>

void random_bytes(uint8_t* dst, unsigned int size) {
  const int ret = getrandom(dst, size, GRND_NONBLOCK);
  if (ret == -1) {
    logger_log(LOGGER_ERROR, "Failed to get random data: %d", errno);
  }
}
#else /* older glibc */
#include <sys/syscall.h>
#include <unistd.h>

void random_bytes(uint8_t* dst, unsigned int size) {
  syscall(SYS_getrandom, dst, size, 0);
}
#endif
#endif
