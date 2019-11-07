#ifndef LOGGER_H
#define LOGGER_H

#ifdef HAVE_ZFLOG
#include "zf_log/zf_log/zf_log.h"

#define LOGGER_DEBUG ZF_LOG_DEBUG
#define LOGGER_INFO ZF_LOG_INFO
#define LOGGER_WARNING ZF_LOG_WARN
#define LOGGER_ERROR ZF_LOG_ERROR

#define logger_log(lvl, ...) ZF_LOG_WRITE(lvl, "bfe", __VA_ARGS__)
#else
#define LOGGER_DEBUG 0
#define LOGGER_INFO 0
#define LOGGER_WARNING 0
#define LOGGER_ERROR 0

#define logger_log(lvl, ...)
#endif

#endif
