#ifndef DAWN_LOG_H
#define DAWN_LOG_H

enum {
    DAWN_LOG_LEVEL_NONE    = 0,
    DAWN_LOG_LEVEL_ERROR   = 1,
    DAWN_LOG_LEVEL_WARNING = 2,
    DAWN_LOG_LEVEL_INFO    = 3,
    DAWN_LOG_LEVEL_DEBUG   = 4,
};

#ifdef DAWN_VERBOSE_LOGS
#define DAWN_LOG_ERROR(...)     dawn_log(DAWN_LOG_LEVEL_ERROR, __FILE__, __func__, __LINE__, __VA_ARGS__)
#define DAWN_LOG_WARNING(...)   dawn_log(DAWN_LOG_LEVEL_WARNING, __FILE__, __func__, __LINE__, __VA_ARGS__)
#define DAWN_LOG_INFO(...)      dawn_log(DAWN_LOG_LEVEL_INFO, __FILE__, __func__, __LINE__, __VA_ARGS__)
#define DAWN_LOG_DEBUG(...)     dawn_log(DAWN_LOG_LEVEL_DEBUG, __FILE__, __func__, __LINE__, __VA_ARGS__)

void dawn_log(int log_level, const char *file, const char *function, int line, const char *format, ...);
#else
#define DAWN_LOG_ERROR(...)     dawn_log(DAWN_LOG_LEVEL_ERROR, __VA_ARGS__)
#define DAWN_LOG_WARNING(...)   dawn_log(DAWN_LOG_LEVEL_WARNING, __VA_ARGS__)
#define DAWN_LOG_INFO(...)      dawn_log(DAWN_LOG_LEVEL_INFO, __VA_ARGS__)
#define DAWN_LOG_DEBUG(...)     dawn_log(DAWN_LOG_LEVEL_DEBUG, __VA_ARGS__)

#ifdef DAWN_NO_DEBUG_LOGS
#undef DAWN_LOG_DEBUG
#define DAWN_LOG_DEBUG(...)
#endif

void dawn_log(int log_level, const char *format, ...);
#endif
void dawn_set_log_level(int log_level);


#endif /* DAWN_LOG_H */
