#ifndef DAWN_LOG_H
#define DAWN_LOG_H

enum {
    DAWN_LOG_LEVEL_NONE    = 0,
    DAWN_LOG_LEVEL_ERROR   = 1,
    DAWN_LOG_LEVEL_WARNING = 2,
    DAWN_LOG_LEVEL_INFO    = 3,
    DAWN_LOG_LEVEL_DEBUG   = 4,
};

#define DAWN_LOG_ERROR(...)     dawn_log(DAWN_LOG_LEVEL_ERROR, __VA_ARGS__)
#define DAWN_LOG_WARNING(...)   dawn_log(DAWN_LOG_LEVEL_WARNING, __VA_ARGS__)
#define DAWN_LOG_INFO(...)      dawn_log(DAWN_LOG_LEVEL_INFO, __VA_ARGS__)
#define DAWN_LOG_DEBUG(...)     dawn_log(DAWN_LOG_LEVEL_DEBUG, __VA_ARGS__)

void dawn_set_log_level(int log_level);
void dawn_log(int log_level, const char *format, ...);

#endif /* DAWN_LOG_H */
