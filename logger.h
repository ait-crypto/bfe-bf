#ifndef LOGGER_H
#define LOGGER_H

#include "zf_log/zf_log/zf_log.h"

#define LOGGER_DEBUG ZF_LOG_DEBUG
#define LOGGER_INFO ZF_LOG_INFO
#define LOGGER_WARNING ZF_LOG_WARN
#define LOGGER_ERROR ZF_LOG_ERROR

#define logger_log(lvl, ...) ZF_LOG_WRITE(lvl, "bfe", __VA_ARGS__)

#endif
