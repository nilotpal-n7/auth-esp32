// =============================================================================
// wifi_manager.h — WiFi/BLE Network Manager with NVS Persistence
// =============================================================================
#pragma once

#include <Arduino.h>

// Max saved WiFi networks in NVS
#define WIFIMGR_MAX_SAVED     8
// Max scan results displayed
#define WIFIMGR_MAX_SCAN      10
// Max SSID length
#define WIFIMGR_SSID_LEN      33
// Max password length
#define WIFIMGR_PASS_LEN      65

// Saved WiFi entry
struct WifiEntry {
    char ssid[WIFIMGR_SSID_LEN];
    char password[WIFIMGR_PASS_LEN];
    bool valid;
};

// Scan result entry
struct WifiScanResult {
    char ssid[WIFIMGR_SSID_LEN];
    int  rssi;
    bool encrypted;  // true if password required
    bool saved;      // true if SSID is in our saved list
};

// Connection page sub-states
enum ConnPageMode {
    CONN_MODE_OVERVIEW,       // Show saved WiFi + BLE status, toggle
    CONN_MODE_SAVED_MENU,     // Sub-menu for a saved network (Connect/Forget/Change Pass)
    CONN_MODE_SCANNING,       // Scanning in progress
    CONN_MODE_SCAN_RESULTS,   // Show scan results
    CONN_MODE_WAIT_PASSWORD,  // Waiting for serial password input
    CONN_MODE_CONNECTING,     // Attempting connection
};

// Initialize the WiFi manager (loads saved networks from NVS)
void wifiMgrInit();

// Get count of saved WiFi networks
int wifiMgrSavedCount();

// Get a saved WiFi entry by index
bool wifiMgrGetSaved(int index, WifiEntry* entry);

// Delete a saved WiFi entry by index
bool wifiMgrDeleteSaved(int index);

// Start an async WiFi scan
void wifiMgrStartScan();

// Check if scan is complete. Returns true if done.
bool wifiMgrScanDone();

// Get scan results. Returns count.
int wifiMgrGetScanResults(WifiScanResult* results, int maxResults);

// Connect to a saved network by index. Returns true on success.
bool wifiMgrConnectSaved(int index);

// Save a new WiFi network (SSID + password) to NVS. Returns index or -1.
int wifiMgrSaveNetwork(const char* ssid, const char* password);

// Connect to an SSID with a password (and save if successful). Returns true on success.
bool wifiMgrConnectNew(const char* ssid, const char* password);

// Check if serial has a complete line ready, and read it into buf.
// Returns true if a line was read.
bool wifiMgrReadSerialLine(char* buf, size_t maxLen);

// Get the current connection page mode
ConnPageMode wifiMgrGetMode();

// Set the current connection page mode
void wifiMgrSetMode(ConnPageMode mode);

// Get the SSID currently pending password input
const char* wifiMgrGetPendingSSID();

// Set an SSID that needs password input via serial
void wifiMgrSetPendingSSID(const char* ssid);
