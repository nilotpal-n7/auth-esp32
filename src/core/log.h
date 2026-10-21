// =============================================================================
// core/log.h — serial logging plus a small ring buffer shown on the OLED
//
// The event log survives reboots: it lives in RTC memory (kept through resets
// and crashes) and is copied to NVS a few seconds after each change (kept
// through power loss).
// =============================================================================
#pragma once

#include <Arduino.h>

#define LOG_LINES       24
#define LOG_LINE_LEN    44

// Print "[tag] message" to serial.
void logf(const char* tag, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

// Adds a line to the on-device event log (and serial), stamped with the
// local time "HH:MM", or the uptime "+M:SS" until the clock is set.
void logEvent(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

int         logCount();
const char* logLine(int index);   // 0 = oldest

void logInit();      // after NVS init: restore the previous boot's events
void logLoop();      // saves to NVS once changes have settled
void logFlush();     // save now (before a reboot / firmware update)
void logClear();

// Raw console output (no tag), serialised with log output.
void consolef(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void consoleWrite(const char* s);

void logHex(const char* tag, const char* label, const uint8_t* data, size_t len);
