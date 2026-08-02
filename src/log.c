#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int g_json;
static int g_verbose;

static const char *level_name(wcat_log_level level)
{
    switch (level) {
    case WCAT_LOG_ERROR: return "error";
    case WCAT_LOG_WARN: return "warn";
    case WCAT_LOG_INFO: return "info";
    case WCAT_LOG_DEBUG: return "debug";
    default: return "unknown";
    }
}

static void json_escape(FILE *fp, const char *s)
{
    for (; s != NULL && *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', fp);
            fputc(c, fp);
        } else if (c == '\n') {
            fputs("\\n", fp);
        } else if (c == '\r') {
            fputs("\\r", fp);
        } else if (c == '\t') {
            fputs("\\t", fp);
        } else if (iscntrl(c)) {
            fprintf(fp, "\\u%04x", c);
        } else {
            fputc(c, fp);
        }
    }
}

void wcat_log_init(bool json, bool verbose)
{
    g_json = json ? 1 : 0;
    g_verbose = verbose ? 1 : 0;
}

void wcat_log(wcat_log_level level, const char *event, const char *fmt, ...)
{
    va_list ap;
    char msg[1024];
    time_t now;

    if (level == WCAT_LOG_DEBUG && !g_verbose) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (g_json) {
        now = time(NULL);
        fprintf(stderr, "{\"ts\":%ld,\"level\":\"%s\",\"event\":\"", (long)now,
                level_name(level));
        json_escape(stderr, event);
        fputs("\",\"message\":\"", stderr);
        json_escape(stderr, msg);
        fputs("\"}\n", stderr);
    } else {
        fprintf(stderr, "wcat: %s: %s\n", level_name(level), msg);
    }
}

void wcat_log_errno(const char *event, const char *context)
{
    wcat_log(WCAT_LOG_ERROR, event, "%s: %s", context, strerror(errno));
}

void wcat_hexdump(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;

    fprintf(stderr, "%s %zu bytes\n", label, len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            fprintf(stderr, "%08zx  ", i);
        }
        fprintf(stderr, "%02x ", buf[i]);
        if (i % 16 == 15 || i + 1 == len) {
            fputc('\n', stderr);
        }
    }
}

