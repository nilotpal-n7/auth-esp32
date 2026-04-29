// =============================================================================
// ntp_sync.cpp — WiFi + NTP Time Synchronization (Multi-WiFi Fallback)
// =============================================================================

#include "ntp_sync.h"
#include "config.h"
#include <WiFi.h>
#include "time.h"

static bool s_timeSynced = false;

// Try connecting to a single WiFi network. Returns true if connected.
static bool tryConnect(const char* ssid, const char* password) {
    Serial.printf("[NTP] Trying: %s ... ", ssid);

    WiFi.begin(ssid, password);

    unsigned long startMs = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - startMs > WIFI_CONNECT_TIMEOUT_MS) {
            Serial.println("TIMEOUT");
            WiFi.disconnect(true);
            return false;
        }
        delay(250);
    }

    Serial.printf("CONNECTED (IP: %s)\n", WiFi.localIP().toString().c_str());
    return true;
}

NtpStatus syncTimeNTP() {
    Serial.println("[NTP] Starting multi-WiFi connection...");
    Serial.printf("[NTP] %d network(s) configured.\n", WIFI_CREDENTIAL_COUNT);

    WiFi.mode(WIFI_STA);

    // Try each configured network in order
    bool connected = false;
    for (int i = 0; i < WIFI_CREDENTIAL_COUNT; i++) {
        if (tryConnect(WIFI_CREDENTIALS[i].ssid, WIFI_CREDENTIALS[i].password)) {
            connected = true;
            break;
        }
    }

    if (!connected) {
        Serial.println("[NTP] All WiFi networks failed!");
        WiFi.mode(WIFI_OFF);
        return NTP_WIFI_FAILED;
    }

    // Configure and sync time
    configTime(NTP_GMT_OFFSET, NTP_DAYLIGHT_OFFSET, NTP_SERVER);

    // Wait for valid time
    struct tm timeinfo;
    unsigned long startMs = millis();
    while (!getLocalTime(&timeinfo, 1000)) { // 1 second timeout per call to avoid 5s blocking
        if (millis() - startMs > NTP_SYNC_TIMEOUT_MS) {
            Serial.println("[NTP] Time sync timeout!");
            WiFi.disconnect(true);
            WiFi.mode(WIFI_OFF);
            return NTP_SYNC_FAILED;
        }
    }

    Serial.printf("[NTP] Time synced: %04d-%02d-%02d %02d:%02d:%02d\n",
                  timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                  timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

    s_timeSynced = true;

#if !ENABLE_OTA
    // Disconnect WiFi — we only needed the clock sync
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    Serial.println("[NTP] WiFi disconnected. Running offline.");
#else
    Serial.println("[NTP] WiFi kept ALIVE for OTA updates.");
#endif

    return NTP_OK;
}

time_t getUTCTimestamp() {
    if (!s_timeSynced) return 0;

    time_t now;
    time(&now);
    // configTime already applied the GMT offset to the system clock,
    // but TOTP needs raw UTC. Subtract the offset back out.
    return now - NTP_GMT_OFFSET;
}

bool isTimeSynced() {
    return s_timeSynced;
}

void getLocalTimeString(char* buf, size_t maxLen) {
    if (!s_timeSynced) {
        if (maxLen > 0) buf[0] = '\0';
        return;
    }
    struct tm timeinfo;
    if (getLocalTime(&timeinfo, 0)) {
        snprintf(buf, maxLen, "%02d:%02d", timeinfo.tm_hour, timeinfo.tm_min);
    } else {
        if (maxLen > 0) buf[0] = '\0';
    }
}

bool wifiReconnect() {
    if (WiFi.status() == WL_CONNECTED) return true;
    
    Serial.println("[WIFI] Reconnecting for tunnel...");
    WiFi.mode(WIFI_STA);
    
    for (int i = 0; i < WIFI_CREDENTIAL_COUNT; i++) {
        if (tryConnect(WIFI_CREDENTIALS[i].ssid, WIFI_CREDENTIALS[i].password)) {
            return true;
        }
    }
    
    Serial.println("[WIFI] All networks failed!");
    return false;
}
