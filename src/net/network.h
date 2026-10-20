// =============================================================================
// net/network.h — WiFi (saved networks, background reconnect), clock, OTA
// =============================================================================
#pragma once

#include <Arduino.h>
#include <time.h>

namespace network {

void init();
void loop();

bool connected();
const char* ssid();                 // current network ("" if none)
String ip();

// Blocking connect to the strongest saved network in range.
bool ensureConnected();
// Request a background (re)connect attempt as soon as possible.
void reconnectSoon();

// --- Clock (UTC) ---
bool   timeValid();
time_t now();                       // UTC seconds, 0 if unknown
void   setTimeUtc(time_t utc);      // manual set (e.g. from the console)
void   applyTimezone();             // re-read settings::timezone()
void   localClock(char* out, size_t cap);   // "HH:MM" or ""

// --- Saved networks ---
int  savedCount();
bool savedSsid(int index, char* out, size_t cap);
bool savedAdd(const char* ssid, const char* password);
bool savedRemove(int index);
void savedResetToDefaults();        // re-import the .env list

// --- OTA ---
bool otaEnabled();
bool otaActive();
typedef void (*OtaProgressFn)(unsigned done, unsigned total);
void setOtaProgressHandler(OtaProgressFn fn);

}  // namespace network
