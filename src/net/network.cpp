#include "net/network.h"
#include "config.h"
#include "core/log.h"
#include "core/settings.h"

#include <ArduinoOTA.h>
#include <Preferences.h>
#include <WiFi.h>
#include <sys/time.h>

namespace network {

struct SavedNetwork {
    char ssid[33];
    char pass[65];
};

// Trailing empty entry keeps the array valid when .env lists none.
static const SavedNetwork DEFAULT_NETWORKS[] = { SECRET_WIFI_NETWORKS {"", ""} };
static const int DEFAULT_COUNT = sizeof(DEFAULT_NETWORKS) / sizeof(DEFAULT_NETWORKS[0]) - 1;

static Preferences  s_prefs;
static SavedNetwork s_saved[WIFI_MAX_SAVED];
static int          s_savedCount = 0;

enum class Bg : uint8_t { Idle, Scanning, Connecting };
static Bg       s_bg = Bg::Idle;
static uint32_t s_bgSince = 0;
static int      s_bgIndex = -1;
static uint32_t s_nextAttempt = 0;
static uint32_t s_backoff = 5000;
static bool     s_timeSet = false;
static bool     s_otaReady = false;
static bool     s_otaActive = false;
static OtaProgressFn s_otaProgress = nullptr;

// --- Persistence -------------------------------------------------------------

static void persist() {
    s_prefs.putInt("n", s_savedCount);
    for (int i = 0; i < WIFI_MAX_SAVED; i++) {
        char key[16];
        snprintf(key, sizeof(key), "w%d", i);
        if (i < s_savedCount) s_prefs.putBytes(key, &s_saved[i], sizeof(SavedNetwork));
        else if (s_prefs.isKey(key)) s_prefs.remove(key);
    }
}

static void load() {
    s_savedCount = s_prefs.getInt("n", -1);
    if (s_savedCount < 0) {
        savedResetToDefaults();
        return;
    }
    if (s_savedCount > WIFI_MAX_SAVED) s_savedCount = WIFI_MAX_SAVED;
    for (int i = 0; i < s_savedCount; i++) {
        char key[16];
        snprintf(key, sizeof(key), "w%d", i);
        if (s_prefs.getBytes(key, &s_saved[i], sizeof(SavedNetwork)) != sizeof(SavedNetwork)) {
            s_savedCount = i;
            break;
        }
    }
}

void savedResetToDefaults() {
    s_savedCount = 0;
    for (int i = 0; i < DEFAULT_COUNT && i < WIFI_MAX_SAVED; i++) {
        memset(&s_saved[i], 0, sizeof(SavedNetwork));
        strlcpy(s_saved[i].ssid, DEFAULT_NETWORKS[i].ssid, sizeof(s_saved[i].ssid));
        strlcpy(s_saved[i].pass, DEFAULT_NETWORKS[i].pass, sizeof(s_saved[i].pass));
        s_savedCount++;
    }
    persist();
    logf("NET", "Imported %d network(s) from .env", s_savedCount);
}

int savedCount() { return s_savedCount; }

bool savedSsid(int i, char* out, size_t cap) {
    if (i < 0 || i >= s_savedCount) return false;
    strlcpy(out, s_saved[i].ssid, cap);
    return true;
}

bool savedAdd(const char* ssid, const char* pass) {
    if (!ssid[0] || strlen(ssid) > 32 || strlen(pass) > 64) return false;
    int idx = -1;
    for (int i = 0; i < s_savedCount; i++) if (!strcmp(s_saved[i].ssid, ssid)) idx = i;
    if (idx < 0) {
        if (s_savedCount >= WIFI_MAX_SAVED) return false;
        idx = s_savedCount++;
    }
    memset(&s_saved[idx], 0, sizeof(SavedNetwork));
    strlcpy(s_saved[idx].ssid, ssid, sizeof(s_saved[idx].ssid));
    strlcpy(s_saved[idx].pass, pass, sizeof(s_saved[idx].pass));
    persist();
    reconnectSoon();
    return true;
}

bool savedRemove(int i) {
    if (i < 0 || i >= s_savedCount) return false;
    for (int j = i; j < s_savedCount - 1; j++) s_saved[j] = s_saved[j + 1];
    s_savedCount--;
    persist();
    return true;
}

// --- Connection --------------------------------------------------------------

bool connected() { return WiFi.status() == WL_CONNECTED; }

const char* ssid() {
    static char cur[33];
    if (!connected()) return "";
    strlcpy(cur, WiFi.SSID().c_str(), sizeof(cur));
    return cur;
}

String ip() { return connected() ? WiFi.localIP().toString() : String(""); }

void reconnectSoon() { s_nextAttempt = millis(); s_backoff = 5000; }

// Best saved network among `found` scan results (frees the scan list).
static int pickFromScan(int found) {
    int best = -1, bestRssi = -1000;
    for (int n = 0; n < found; n++) {
        String s = WiFi.SSID(n);
        for (int i = 0; i < s_savedCount; i++) {
            if (s == s_saved[i].ssid && WiFi.RSSI(n) > bestRssi) {
                best = i;
                bestRssi = WiFi.RSSI(n);
            }
        }
    }
    WiFi.scanDelete();
    return best;
}

static void startOta() {
    if (s_otaReady || !otaEnabled()) return;
    ArduinoOTA.setHostname(FW_NAME);
    ArduinoOTA.setPassword(SECRET_OTA_PASSWORD);
    ArduinoOTA.onStart([]() {
        s_otaActive = true;
        logEvent("OTA update started");
    });
    ArduinoOTA.onEnd([]() { logEvent("OTA done, rebooting"); logFlush(); });
    ArduinoOTA.onProgress([](unsigned done, unsigned total) {
        if (s_otaProgress) s_otaProgress(done, total);
    });
    ArduinoOTA.onError([](ota_error_t e) {
        s_otaActive = false;
        logEvent("OTA failed (%u)", (unsigned)e);
    });
    ArduinoOTA.begin();
    s_otaReady = true;
    logf("NET", "OTA enabled at %s.local", FW_NAME);
}

static void onConnected(int idx) {
    logEvent("WiFi %s", s_saved[idx].ssid);
    logf("NET", "IP %s", WiFi.localIP().toString().c_str());
    startOta();
}

bool ensureConnected() {
    // Let a background attempt finish first.
    while (s_bg != Bg::Idle) { loop(); delay(50); }
    if (connected()) return true;
    if (s_savedCount == 0) {
        logf("NET", "No saved WiFi networks (use `wifi add`)");
        return false;
    }
    int idx = pickFromScan(WiFi.scanNetworks(false, false));
    if (idx < 0) {
        logf("NET", "No saved network in range");
        return false;
    }
    logf("NET", "Connecting to %s ...", s_saved[idx].ssid);
    WiFi.begin(s_saved[idx].ssid, s_saved[idx].pass);
    uint32_t start = millis();
    while (!connected() && millis() - start < WIFI_CONNECT_TIMEOUT_MS) delay(100);
    if (!connected()) {
        logf("NET", "Connection to %s failed", s_saved[idx].ssid);
        WiFi.disconnect();
        return false;
    }
    onConnected(idx);
    return true;
}

void init() {
    s_prefs.begin("wifi", false);
    load();
    WiFi.mode(WIFI_STA);
    WiFi.setHostname(FW_NAME);
    WiFi.setAutoReconnect(false);  // reconnection is handled by loop()
    WiFi.setSleep(true);   // modem sleep is required for WiFi/BLE coexistence
    applyTimezone();
    s_nextAttempt = 0;
}

static void backoff() {
    s_bg = Bg::Idle;
    s_nextAttempt = millis() + s_backoff;
    s_backoff = s_backoff < 120000 ? s_backoff * 2 : 120000;
}

// Non-blocking background connection state machine.
void loop() {
    switch (s_bg) {
        case Bg::Idle:
            if (connected()) {
                s_backoff = 5000;
                if (s_otaReady) ArduinoOTA.handle();
            } else if (s_savedCount > 0 && (int32_t)(millis() - s_nextAttempt) >= 0) {
                WiFi.scanNetworks(true, false);
                s_bg = Bg::Scanning;
                s_bgSince = millis();
            }
            break;
        case Bg::Scanning: {
            int found = WiFi.scanComplete();
            if (found == WIFI_SCAN_RUNNING) {
                if (millis() - s_bgSince > 15000) { WiFi.scanDelete(); backoff(); }
                break;
            }
            s_bgIndex = found > 0 ? pickFromScan(found) : -1;
            if (found <= 0) WiFi.scanDelete();
            if (s_bgIndex < 0) { backoff(); break; }
            WiFi.begin(s_saved[s_bgIndex].ssid, s_saved[s_bgIndex].pass);
            s_bg = Bg::Connecting;
            s_bgSince = millis();
            break;
        }
        case Bg::Connecting:
            if (connected()) {
                s_bg = Bg::Idle;
                s_backoff = 5000;
                onConnected(s_bgIndex);
            } else if (millis() - s_bgSince > WIFI_CONNECT_TIMEOUT_MS) {
                logf("NET", "Connection to %s timed out", s_saved[s_bgIndex].ssid);
                WiFi.disconnect();
                backoff();
            }
            break;
    }
    if (!s_timeSet && timeValid()) {
        s_timeSet = true;
        char buf[32];
        time_t t = now();
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", gmtime(&t));
        logEvent("Clock synced");
        logf("NET", "Time: %s", buf);
    }
}

// --- Clock -------------------------------------------------------------------

bool timeValid() { return time(nullptr) > 1700000000; }

time_t now() { return timeValid() ? time(nullptr) : 0; }

void setTimeUtc(time_t utc) {
    timeval tv = {utc, 0};
    settimeofday(&tv, nullptr);
}

void applyTimezone() {
    // Sets TZ and (re)starts SNTP; time() itself is always UTC.
    configTzTime(settings::timezone(), NTP_SERVER_1, NTP_SERVER_2);
}

void localClock(char* out, size_t cap) {
    if (!timeValid()) { if (cap) out[0] = '\0'; return; }
    time_t t = time(nullptr);
    struct tm lt;
    localtime_r(&t, &lt);
    strftime(out, cap, "%H:%M", &lt);
}

// --- OTA ---------------------------------------------------------------------

bool otaEnabled() { return SECRET_OTA_PASSWORD[0] != '\0'; }
bool otaActive() { return s_otaActive; }
void setOtaProgressHandler(OtaProgressFn fn) { s_otaProgress = fn; }

}  // namespace network
