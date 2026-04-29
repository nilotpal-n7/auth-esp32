// =============================================================================
// ntp_sync.h — WiFi + NTP Time Synchronization
// =============================================================================
#pragma once

#include <Arduino.h>

// Status codes for NTP sync
enum NtpStatus {
    NTP_OK,
    NTP_WIFI_FAILED,
    NTP_SYNC_FAILED,
};

// Connect to WiFi, sync time via NTP, then disconnect WiFi to save memory.
// Returns NTP_OK on success, error code on failure.
NtpStatus syncTimeNTP();

// Get the current UTC Unix timestamp (seconds since epoch).
// Returns 0 if time has not been synced.
time_t getUTCTimestamp();

// Check if time has been successfully synced.
bool isTimeSynced();

// Format current time as a string (HH:MM:SS) in local timezone
void getLocalTimeString(char* buf, size_t maxLen);

// Reconnect WiFi (for caBLE tunnel). Returns true if connected.
// Does NOT disconnect after — caller is responsible.
bool wifiReconnect();
