#include "dawn_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

static int dawn_log_level = DAWN_LOG_LEVEL_WARNING;

void dawn_set_log_level(int log_level)
{
    dawn_log_level = log_level;
}

void dawn_log(int log_level, const char *format, ...)
{
    char *message;
    va_list ptr;

    if (log_level <= dawn_log_level) {
        va_start(ptr, format);
        vasprintf(&message, format, ptr);
        va_end(ptr);

#ifdef DAWN_LOG_TO_SYSLOG
        int log_level_map[] = {
            [DAWN_LOG_LEVEL_DEBUG]   = LOG_DEBUG,
            [DAWN_LOG_LEVEL_INFO]    = LOG_INFO,
            [DAWN_LOG_LEVEL_WARNING] = LOG_WARNING,
            [DAWN_LOG_LEVEL_ERROR]   = LOG_ERR,
        };

        syslog(log_level_map[log_level], "%s", message);
#else
        fprintf(stderr, "%s\n", message);
#endif

        free(message);
    }
}
