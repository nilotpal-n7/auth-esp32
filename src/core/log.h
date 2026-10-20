// =============================================================================
// core/log.h — serial logging plus a small ring buffer shown on the OLED
// =============================================================================
#pragma once

#include <Arduino.h>

#define LOG_LINES       12
#define LOG_LINE_LEN    40

// Print "[tag] message" to serial. Also kept in the on-device log if `keep`.
void logf(const char* tag, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

// Same as logf, and also adds a short line to the on-device event log.
void logEvent(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

int         logCount();
const char* logLine(int index);   // 0 = oldest

// Raw console output (no tag), serialised with log output.
void consolef(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void consoleWrite(const char* s);

void logHex(const char* tag, const char* label, const uint8_t* data, size_t len);
