#define _GNU_SOURCE
#include <time.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>

#define log_debug(fmt, ...) log_console_level(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)  log_console_level(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...)  log_console_level(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_console_level(LOG_ERROR, fmt, ##__VA_ARGS__)

typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } log_level_t;

static const char* level_names[] = {"DEBUG","INFO","WARN","ERROR"};
static const char* level_colours[] = {"\033[36m","\033[32m","\033[33m","\033[31m"};
static const char* colour_reset = "\033[0m";

static int logfd_console = -1;
static int logfd_file = -1;
static int loglevel = 1;

static void log_timestamp(char* buf, size_t sz) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tm);
}

static void log_console_level(log_level_t level, const char *fmt, ...) {
    if (level < loglevel) {
        return;
    }
    char ts[20];
    log_timestamp(ts, sizeof(ts));

    // lazy open
    if (logfd_console < 0) logfd_console = open("/dev/console", O_WRONLY | O_CLOEXEC);
    if (logfd_file < 0) {
        mkdir("/log", 0755);
        logfd_file = open("/log/init.log", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);
    }

    va_list ap;

    if (logfd_console >= 0) {
        va_start(ap, fmt);
        dprintf(logfd_console, "%s%s [%s] ", level_colours[level], ts, level_names[level]);
        vdprintf(logfd_console, fmt, ap);
        dprintf(logfd_console, "%s", colour_reset);
        va_end(ap);
    }

    if (logfd_file >= 0) {
        va_start(ap, fmt);
        dprintf(logfd_file, "%s [%s] ", ts, level_names[level]);
        vdprintf(logfd_file, fmt, ap);
        va_end(ap);
    }
}