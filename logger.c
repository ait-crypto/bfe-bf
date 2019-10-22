#include <stdio.h>
#include <time.h>
#include <string.h>
#include "logger.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

const char LOGGER_DEBUG[] = "DEBUG";
const char LOGGER_INFO[] = "INFO";
const char LOGGER_WARNING[] = "WARNING";
const char LOGGER_ERROR[] = "ERROR";

void logger_log(const char* level, const char* message) {
    char formattedTime[500];
    time_t t = time(NULL);
    struct tm *p = localtime(&t);
    strftime(formattedTime, 500, "%d/%m/%Y %H:%M:%S", p);

    char colorCode[9];
    if (strcmp(level, LOGGER_WARNING) == 0) {
        strcpy(colorCode, ANSI_COLOR_YELLOW);
    } else if (strcmp(level, LOGGER_ERROR) == 0) {
        strcpy(colorCode, ANSI_COLOR_RED);
    } else {
        colorCode[0] = '\0';
    }

    printf("%s[%s]%s %s %s\n", colorCode, level, ANSI_COLOR_RESET, formattedTime, message);
}