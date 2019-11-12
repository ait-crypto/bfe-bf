#include "util.h"

#if defined(__linux__) && defined(HAVE_SYS_RANDOM_H) && defined(HAVE_GETRANDOM)
#include <sys/random.h>

int random_bytes(uint8_t* dst, size_t len) {
  const ssize_t ret = getrandom(dst, len, GRND_NONBLOCK);
  if (ret < 0 || (size_t)ret != len) {
    return 0;
  }
  return 1;
}
#elif defined(__linux__) || defined(__APPLE__)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#if defined(__linux__)
#include <linux/random.h>
#include <sys/ioctl.h>
#endif

#if !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif
#if !defined(O_CLOEXEC)
#define O_CLOEXEC 0
#endif

int random_bytes(uint8_t* dst, size_t len) {
  int fd;
  while ((fd = open("/dev/urandom", O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0)) == -1) {
    // check if we should restart
    if (errno != EINTR) {
      return 0;
    }
  }
#if O_CLOEXEC == 0
  fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif

#if defined(__linux__)
  int cnt = 0;
  if (ioctl(fd, RNDGETENTCNT, &cnt) == -1) {
    // not ready
    close(fd);
    return 0;
  }
#endif

  while (len) {
    const ssize_t ret = read(fd, dst, len);
    if (ret == -1) {
      if (errno == EAGAIN || errno == EINTR) {
        // retry
        continue;
      }
      close(fd);
      return 0;
    }

    dst += ret;
    len -= ret;
  }

  close(fd);
  return 1;
}
#else
#error "Unsupported OS! Please implement random_bytes."
#endif
