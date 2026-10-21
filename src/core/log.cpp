#include "core/log.h"
#include <stdarg.h>
#include <time.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

static char  s_lines[LOG_LINES][LOG_LINE_LEN];
static int   s_head = 0;
static int   s_count = 0;
static SemaphoreHandle_t s_mutex = nullptr;

static void lock() {
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
}
static void unlock() { xSemaphoreGive(s_mutex); }

void logf(const char* tag, const char* fmt, ...) {
    char buf[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    lock();
    Serial.printf("[%s] %s\n", tag, buf);
    unlock();
}

// "14:39" once the clock is set (TZ applies), else uptime "+3:05" (min:sec).
static void stamp(char* out, size_t cap) {
    time_t t = time(nullptr);
    if (t > 1700000000) {
        struct tm lt;
        localtime_r(&t, &lt);
        strftime(out, cap, "%H:%M", &lt);
    } else {
        uint32_t s = millis() / 1000;
        snprintf(out, cap, "+%lu:%02lu", (unsigned long)(s / 60), (unsigned long)(s % 60));
    }
}

void logEvent(const char* fmt, ...) {
    char msg[LOG_LINE_LEN], ts[12], buf[LOG_LINE_LEN + 12];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    stamp(ts, sizeof(ts));
    snprintf(buf, sizeof(buf), "%s %s", ts, msg);
    lock();
    Serial.printf("[EVENT] %s\n", buf);
    strlcpy(s_lines[s_head], buf, LOG_LINE_LEN);
    s_head = (s_head + 1) % LOG_LINES;
    if (s_count < LOG_LINES) s_count++;
    unlock();
}

int logCount() { return s_count; }

const char* logLine(int index) {
    if (index < 0 || index >= s_count) return "";
    int oldest = (s_head - s_count + LOG_LINES) % LOG_LINES;
    return s_lines[(oldest + index) % LOG_LINES];
}

void logHex(const char* tag, const char* label, const uint8_t* data, size_t len) {
    lock();
    Serial.printf("[%s] %s (%u):", tag, label, (unsigned)len);
    for (size_t i = 0; i < len; i++) Serial.printf(" %02X", data[i]);
    Serial.println();
    unlock();
}

void consolef(const char* fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    lock();
    Serial.print(buf);
    unlock();
}

void consoleWrite(const char* s) {
    lock();
    Serial.print(s);
    unlock();
}
