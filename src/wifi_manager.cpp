// =============================================================================
// wifi_manager.cpp — WiFi/BLE Network Manager with NVS Persistence
// =============================================================================

#include "wifi_manager.h"
#include "config.h"
#include "logger.h"
#include <WiFi.h>
#include <Preferences.h>

// NVS namespace for saved WiFi networks
static Preferences s_prefs;
static WifiEntry   s_saved[WIFIMGR_MAX_SAVED];
static int         s_savedCount = 0;

// Scan state
static bool        s_scanStarted = false;
static WifiScanResult s_scanResults[WIFIMGR_MAX_SCAN];
static int         s_scanResultCount = 0;

// Connection page state
static ConnPageMode s_mode = CONN_MODE_OVERVIEW;
static char        s_pendingSSID[WIFIMGR_SSID_LEN] = {0};

// Serial input buffer
static char        s_serialBuf[WIFIMGR_PASS_LEN];
static int         s_serialPos = 0;

// =============================================================================
// NVS PERSISTENCE
// =============================================================================

static void loadFromNVS() {
    s_prefs.begin("wifimgr", true); // read-only
    s_savedCount = s_prefs.getInt("count", 0);
    if (s_savedCount > WIFIMGR_MAX_SAVED) s_savedCount = WIFIMGR_MAX_SAVED;
    
    for (int i = 0; i < s_savedCount; i++) {
        char keySSID[12], keyPass[12];
        snprintf(keySSID, sizeof(keySSID), "ssid%d", i);
        snprintf(keyPass, sizeof(keyPass), "pass%d", i);
        
        String ssid = s_prefs.getString(keySSID, "");
        String pass = s_prefs.getString(keyPass, "");
        
        strncpy(s_saved[i].ssid, ssid.c_str(), WIFIMGR_SSID_LEN - 1);
        s_saved[i].ssid[WIFIMGR_SSID_LEN - 1] = '\0';
        strncpy(s_saved[i].password, pass.c_str(), WIFIMGR_PASS_LEN - 1);
        s_saved[i].password[WIFIMGR_PASS_LEN - 1] = '\0';
        s_saved[i].valid = (strlen(s_saved[i].ssid) > 0);
    }
    s_prefs.end();
    
    Serial.printf("[WIFIMGR] Loaded %d saved network(s) from NVS.\n", s_savedCount);
}

static void saveToNVS() {
    s_prefs.begin("wifimgr", false); // read-write
    s_prefs.putInt("count", s_savedCount);
    
    for (int i = 0; i < s_savedCount; i++) {
        char keySSID[12], keyPass[12];
        snprintf(keySSID, sizeof(keySSID), "ssid%d", i);
        snprintf(keyPass, sizeof(keyPass), "pass%d", i);
        
        s_prefs.putString(keySSID, s_saved[i].ssid);
        s_prefs.putString(keyPass, s_saved[i].password);
    }
    
    // Clear any leftover slots
    for (int i = s_savedCount; i < WIFIMGR_MAX_SAVED; i++) {
        char keySSID[12], keyPass[12];
        snprintf(keySSID, sizeof(keySSID), "ssid%d", i);
        snprintf(keyPass, sizeof(keyPass), "pass%d", i);
        s_prefs.remove(keySSID);
        s_prefs.remove(keyPass);
    }
    
    s_prefs.end();
}

// =============================================================================
// PUBLIC API
// =============================================================================

void wifiMgrInit() {
    memset(s_saved, 0, sizeof(s_saved));
    s_savedCount = 0;
    s_serialPos = 0;
    s_mode = CONN_MODE_OVERVIEW;
    
    loadFromNVS();
    
    // If no saved networks, import the hardcoded ones from config.h
    if (s_savedCount == 0) {
        // Import compile-time credentials as initial saved networks
        for (int i = 0; i < WIFI_CREDENTIAL_COUNT && i < WIFIMGR_MAX_SAVED; i++) {
            strncpy(s_saved[i].ssid, WIFI_CREDENTIALS[i].ssid, WIFIMGR_SSID_LEN - 1);
            strncpy(s_saved[i].password, WIFI_CREDENTIALS[i].password, WIFIMGR_PASS_LEN - 1);
            s_saved[i].valid = true;
            s_savedCount++;
        }
        saveToNVS();
        Serial.printf("[WIFIMGR] Imported %d hardcoded network(s) to NVS.\n", s_savedCount);
    }
}

int wifiMgrSavedCount() {
    return s_savedCount;
}

bool wifiMgrGetSaved(int index, WifiEntry* entry) {
    if (index < 0 || index >= s_savedCount) return false;
    *entry = s_saved[index];
    return true;
}

bool wifiMgrDeleteSaved(int index) {
    if (index < 0 || index >= s_savedCount) return false;
    
    logAdd("Del WiFi: %s", s_saved[index].ssid);
    
    // Shift entries down
    for (int i = index; i < s_savedCount - 1; i++) {
        s_saved[i] = s_saved[i + 1];
    }
    s_savedCount--;
    memset(&s_saved[s_savedCount], 0, sizeof(WifiEntry));
    
    saveToNVS();
    return true;
}

void wifiMgrStartScan() {
    s_scanStarted = true;
    s_scanResultCount = 0;
    WiFi.mode(WIFI_STA);
    WiFi.scanNetworks(true); // async scan
    Serial.println("[WIFIMGR] WiFi scan started (async).");
    logAdd("WiFi scan started");
}

bool wifiMgrScanDone() {
    if (!s_scanStarted) return false;
    
    int result = WiFi.scanComplete();
    if (result == WIFI_SCAN_RUNNING) return false;
    if (result == WIFI_SCAN_FAILED) {
        s_scanStarted = false;
        s_scanResultCount = 0;
        Serial.println("[WIFIMGR] Scan failed!");
        logAdd("WiFi scan failed");
        return true;
    }
    
    // Scan complete, populate results
    s_scanResultCount = 0;
    for (int i = 0; i < result && s_scanResultCount < WIFIMGR_MAX_SCAN; i++) {
        String ssid = WiFi.SSID(i);
        if (ssid.length() == 0) continue; // Skip hidden networks
        
        // Deduplicate (keep strongest signal)
        bool dupe = false;
        for (int j = 0; j < s_scanResultCount; j++) {
            if (strcmp(s_scanResults[j].ssid, ssid.c_str()) == 0) {
                dupe = true;
                break;
            }
        }
        if (dupe) continue;
        
        strncpy(s_scanResults[s_scanResultCount].ssid, ssid.c_str(), WIFIMGR_SSID_LEN - 1);
        s_scanResults[s_scanResultCount].ssid[WIFIMGR_SSID_LEN - 1] = '\0';
        s_scanResults[s_scanResultCount].rssi = WiFi.RSSI(i);
        s_scanResults[s_scanResultCount].encrypted = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
        
        // Check if this SSID is in our saved list
        s_scanResults[s_scanResultCount].saved = false;
        for (int j = 0; j < s_savedCount; j++) {
            if (strcmp(s_saved[j].ssid, s_scanResults[s_scanResultCount].ssid) == 0) {
                s_scanResults[s_scanResultCount].saved = true;
                break;
            }
        }
        
        s_scanResultCount++;
    }
    
    WiFi.scanDelete();
    s_scanStarted = false;
    
    Serial.printf("[WIFIMGR] Scan done: %d network(s) found.\n", s_scanResultCount);
    logAdd("Scan: %d networks", s_scanResultCount);
    return true;
}

int wifiMgrGetScanResults(WifiScanResult* results, int maxResults) {
    int count = (s_scanResultCount < maxResults) ? s_scanResultCount : maxResults;
    memcpy(results, s_scanResults, count * sizeof(WifiScanResult));
    return count;
}

bool wifiMgrConnectSaved(int index) {
    if (index < 0 || index >= s_savedCount) return false;
    
    Serial.printf("[WIFIMGR] Connecting to saved: %s\n", s_saved[index].ssid);
    logAdd("Connecting: %s", s_saved[index].ssid);
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(s_saved[index].ssid, s_saved[index].password);
    
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > 8000) {
            Serial.println("[WIFIMGR] Connection timeout!");
            logAdd("Connect failed!");
            WiFi.disconnect(true);
            return false;
        }
        delay(200);
    }
    
    Serial.printf("[WIFIMGR] Connected! IP: %s\n", WiFi.localIP().toString().c_str());
    logAdd("Connected: %s", s_saved[index].ssid);
    return true;
}

int wifiMgrSaveNetwork(const char* ssid, const char* password) {
    // Check if already exists — update password
    for (int i = 0; i < s_savedCount; i++) {
        if (strcmp(s_saved[i].ssid, ssid) == 0) {
            strncpy(s_saved[i].password, password, WIFIMGR_PASS_LEN - 1);
            s_saved[i].password[WIFIMGR_PASS_LEN - 1] = '\0';
            saveToNVS();
            return i;
        }
    }
    
    // Add new
    if (s_savedCount >= WIFIMGR_MAX_SAVED) {
        Serial.println("[WIFIMGR] Max saved networks reached!");
        return -1;
    }
    
    strncpy(s_saved[s_savedCount].ssid, ssid, WIFIMGR_SSID_LEN - 1);
    s_saved[s_savedCount].ssid[WIFIMGR_SSID_LEN - 1] = '\0';
    strncpy(s_saved[s_savedCount].password, password, WIFIMGR_PASS_LEN - 1);
    s_saved[s_savedCount].password[WIFIMGR_PASS_LEN - 1] = '\0';
    s_saved[s_savedCount].valid = true;
    
    s_savedCount++;
    saveToNVS();
    
    logAdd("Saved WiFi: %s", ssid);
    return s_savedCount - 1;
}

bool wifiMgrConnectNew(const char* ssid, const char* password) {
    Serial.printf("[WIFIMGR] Connecting to new: %s\n", ssid);
    logAdd("Trying: %s", ssid);
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - start > 10000) {
            Serial.println("[WIFIMGR] Connection failed!");
            logAdd("Connect failed!");
            WiFi.disconnect(true);
            return false;
        }
        delay(200);
    }
    
    // Save on success
    wifiMgrSaveNetwork(ssid, password);
    Serial.printf("[WIFIMGR] Connected & saved! IP: %s\n", WiFi.localIP().toString().c_str());
    logAdd("Connected: %s", ssid);
    return true;
}

bool wifiMgrReadSerialLine(char* buf, size_t maxLen) {
    while (Serial.available()) {
        char c = Serial.read();
        
        if (c == '\n' || c == '\r') {
            if (s_serialPos > 0) {
                s_serialBuf[s_serialPos] = '\0';
                strncpy(buf, s_serialBuf, maxLen - 1);
                buf[maxLen - 1] = '\0';
                s_serialPos = 0;
                return true;
            }
        } else if (s_serialPos < (int)(WIFIMGR_PASS_LEN - 1)) {
            s_serialBuf[s_serialPos++] = c;
        }
    }
    return false;
}

ConnPageMode wifiMgrGetMode() {
    return s_mode;
}

void wifiMgrSetMode(ConnPageMode mode) {
    s_mode = mode;
}

const char* wifiMgrGetPendingSSID() {
    return s_pendingSSID;
}

void wifiMgrSetPendingSSID(const char* ssid) {
    strncpy(s_pendingSSID, ssid, WIFIMGR_SSID_LEN - 1);
    s_pendingSSID[WIFIMGR_SSID_LEN - 1] = '\0';
}
