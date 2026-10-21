#include "core/log.h"
#include <stdarg.h>
#include <time.h>
#include <Preferences.h>
#include <esp_attr.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#define LOG_MAGIC      0x4C4F4731u   // "LOG1"
#define LOG_SAVE_DELAY 10000         // ms after the last change
#define LOG_SAVE_MAX   60000         // ms: save at least this often while busy

struct LogRing {
    uint32_t magic;
    int16_t  head;
    int16_t  count;
    char     lines[LOG_LINES][LOG_LINE_LEN];
};

// RTC memory keeps its contents through resets and crashes (not power loss).
RTC_NOINIT_ATTR static LogRing s_ring;
static bool     s_ready = false;     // ring valid (logInit ran)
static bool     s_dirty = false;
static uint32_t s_changedMs = 0, s_dirtySinceMs = 0;
static Preferences s_prefs;
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
    if (s_ready) {
        strlcpy(s_ring.lines[s_ring.head], buf, LOG_LINE_LEN);
        s_ring.head = (s_ring.head + 1) % LOG_LINES;
        if (s_ring.count < LOG_LINES) s_ring.count++;
        s_changedMs = millis();
        if (!s_dirty) s_dirtySinceMs = s_changedMs;
        s_dirty = true;
    }
    unlock();
}

int logCount() { return s_ready ? s_ring.count : 0; }

const char* logLine(int index) {
    if (!s_ready || index < 0 || index >= s_ring.count) return "";
    int oldest = (s_ring.head - s_ring.count + LOG_LINES) % LOG_LINES;
    return s_ring.lines[(oldest + index) % LOG_LINES];
}

static bool ringValid(const LogRing& r) {
    return r.magic == LOG_MAGIC && r.head >= 0 && r.head < LOG_LINES && r.count >= 0 &&
           r.count <= LOG_LINES;
}

void logInit() {
    s_prefs.begin("log", false);
    lock();
    // RTC copy first: after a reset or crash it holds events newer than NVS.
    if (!ringValid(s_ring)) {
        if (s_prefs.getBytes("ring", &s_ring, sizeof(s_ring)) != sizeof(s_ring) || !ringValid(s_ring)) {
            memset(&s_ring, 0, sizeof(s_ring));
            s_ring.magic = LOG_MAGIC;
        }
    }
    for (int i = 0; i < LOG_LINES; i++) s_ring.lines[i][LOG_LINE_LEN - 1] = '\0';
    s_ready = true;
    unlock();
}

static void saveLocked() {
    s_prefs.putBytes("ring", &s_ring, sizeof(s_ring));
    s_dirty = false;
}

void logLoop() {
    if (!s_dirty) return;
    uint32_t now = millis();
    if (now - s_changedMs < LOG_SAVE_DELAY && now - s_dirtySinceMs < LOG_SAVE_MAX) return;
    lock();
    saveLocked();
    unlock();
}

void logFlush() {
    if (!s_ready) return;
    lock();
    if (s_dirty) saveLocked();
    unlock();
}

void logClear() {
    if (!s_ready) return;
    lock();
    memset(&s_ring, 0, sizeof(s_ring));
    s_ring.magic = LOG_MAGIC;
    saveLocked();
    unlock();
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
