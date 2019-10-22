#ifndef MASTER_PROJECT_LOGGER_H
#define MASTER_PROJECT_LOGGER_H

extern const char LOGGER_DEBUG[];
extern const char LOGGER_INFO[];
extern const char LOGGER_WARNING[];
extern const char LOGGER_ERROR[];

void logger_log(const char* level, const char* message);

#endif //MASTER_PROJECT_LOGGER_H
