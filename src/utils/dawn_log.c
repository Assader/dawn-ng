#include "dawn_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

static int dawn_log_level = DAWN_LOG_LEVEL_WARNING;

#ifndef DAWN_LOG_TO_SYSLOG
static char log_level_symbol[] = {
    [DAWN_LOG_LEVEL_DEBUG]   = 'D',
    [DAWN_LOG_LEVEL_INFO]    = 'I',
    [DAWN_LOG_LEVEL_WARNING] = 'W',
    [DAWN_LOG_LEVEL_ERROR]   = 'E',
};
#endif

#ifdef DAWN_VERBOSE_LOGS
void dawn_log(int log_level, const char *file, const char *function, int line, const char *format, ...)
{
    char *message;
    va_list arg_list;

    if (log_level <= dawn_log_level) {
        va_start(arg_list, format);
        vasprintf(&message, format, arg_list);
        va_end(arg_list);

#ifdef DAWN_LOG_TO_SYSLOG
        int log_level_map[] = {
            [DAWN_LOG_LEVEL_DEBUG]   = LOG_DEBUG,
            [DAWN_LOG_LEVEL_INFO]    = LOG_INFO,
            [DAWN_LOG_LEVEL_WARNING] = LOG_WARNING,
            [DAWN_LOG_LEVEL_ERROR]   = LOG_ERR,
        };

        syslog(log_level_map[log_level], "%s:%s:%d: %s", file, function, line, message);
#else
        fprintf(stderr, "%s:%s:%d: <%c> %s\n", file, function, line, log_level_symbol[log_level], message);
#endif

        free(message);
    }
}
#else
void dawn_log(int log_level, const char *format, ...)
{
    char *message;
    va_list arg_list;

    if (log_level <= dawn_log_level) {
        va_start(arg_list, format);
        vasprintf(&message, format, arg_list);
        va_end(arg_list);

#ifdef DAWN_LOG_TO_SYSLOG
        int log_level_map[] = {
            [DAWN_LOG_LEVEL_DEBUG]   = LOG_DEBUG,
            [DAWN_LOG_LEVEL_INFO]    = LOG_INFO,
            [DAWN_LOG_LEVEL_WARNING] = LOG_WARNING,
            [DAWN_LOG_LEVEL_ERROR]   = LOG_ERR,
        };

        syslog(log_level_map[log_level], "%s", message);
#else
        fprintf(stderr, "<%c> %s\n", log_level_symbol[log_level], message);
#endif

        free(message);
    }
}
#endif

void dawn_set_log_level(int log_level)
{
    dawn_log_level = log_level;
}
