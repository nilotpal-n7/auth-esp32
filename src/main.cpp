// =============================================================================
// main.cpp — ESP32 Hardware Authenticator: State Machine Orchestrator
// =============================================================================

#include <Arduino.h>
#include "config.h"
#include "ui.h"
#include "buttons.h"
#include "totp.h"
#include "ntp_sync.h"
#include "credential_store.h"
#include "fido2/crypto.h"
#include "fido2/ble_transport.h"
#include "fido2/cable_tunnel.h"
#include "fido2/ctap2.h"
#include "ota_update.h"
#include "logger.h"
#include "wifi_manager.h"
#include <Wire.h>
#include <WiFi.h>

// =============================================================================
// GLOBAL STATE
// =============================================================================

static AppState        g_state = STATE_BOOT;
static bool            g_autoAllow = false;
static int             g_pageIndex = 0;       // 0=Intro, 1=TOTP, 2=Settings, 3=Logs, 4=Connectivity
static const int       TOTAL_PAGES = 5;
static int             g_totpIndex = 0;       // Currently displayed TOTP account
static int             g_settingsIndex = 0;   // Currently selected setting
static int             g_connIndex = 0;       // Currently selected item on connectivity page
static int             g_scanSelIndex = 0;    // Selected item in scan results
static int             g_savedMenuIndex = 0;  // Selected item in saved network sub-menu
static int             g_savedNetworkIdx = 0; // Which saved network the sub-menu is for
static unsigned long   g_lastUiUpdate = 0;
static const unsigned long UI_REFRESH_MS = 200;

static int             g_totpCount = 0;

// =============================================================================
// BLE COMMAND CALLBACK
// =============================================================================

void onCtapCommand(const uint8_t* data, size_t len) {
    ctap2ProcessCommand(data, len);
}

// =============================================================================
// SETUP
// =============================================================================

void setup() {
    Serial.begin(115200);
    delay(500);

    // Initialize built-in LED (GPIO 2) for heartbeat
    pinMode(2, OUTPUT);

    Serial.println("\n========================================");
    Serial.println("  AuthKey-ESP32 v1.0.0-alpha");
    Serial.println("  Hardware Authenticator");
    Serial.println("========================================\n");

    // Initialize logger
    loggerInit();
    logAdd("System Boot");

    Serial.println("========================================\n");

    // --- 0. HARDWARE DIAGNOSTICS (I2C SCAN) ---
    Serial.println("[DIAG] Scanning I2C bus...");
    Wire.begin(PIN_SDA, PIN_SCL);
    int nDevices = 0;
    for(byte address = 1; address < 127; address++ ) {
        Wire.beginTransmission(address);
        byte error = Wire.endTransmission();
        if (error == 0) {
            Serial.printf("[DIAG] I2C device found at address 0x%02X\n", address);
            nDevices++;
        }
    }
    if (nDevices == 0) Serial.println("[DIAG] ERROR: No I2C devices found! Check OLED wiring (VCC, GND, SDA, SCL).");
    Serial.println("[DIAG] I2C scan complete.\n");

    // --- 1. Initialize Display ---
    uiInit();
    uiDrawBoot();
    delay(1500);

    // --- 2. Initialize Buttons ---
    buttonsInit();
    Serial.println("[MAIN] Buttons initialized.");

    // --- 3. Initialize Credential Store ---
    credStoreInit();

    // --- 4. Initialize Crypto Engine ---
    if (!cryptoInit()) {
        uiDrawMessage("ERROR", "Crypto init failed!", "Check serial log.");
        while (1) delay(1000);
    }

    // --- 5. Initialize TOTP Engine ---
    totpInit();

    // --- 6. Load TOTP accounts from NVS ---
    g_totpCount = credStoreCountTotp();
    if (g_totpCount == 0) {
        // Pre-load a demo account for testing
        // This is the RFC 6238 test vector secret: base32("12345678901234567890")
        credStoreSaveTotp("Demo Account", "GEZDGNBVGY3TQOJQ");
        g_totpCount = 1;
        Serial.println("[MAIN] Pre-loaded demo TOTP account.");
    }

    // --- 7. Sync Time via NTP ---
    g_state = STATE_SYNCING_TIME;
    uiDrawSyncing("Connecting WiFi...");

    NtpStatus ntpResult = syncTimeNTP();
    if (ntpResult == NTP_OK) {
        Serial.println("[MAIN] Time synced successfully.");
    } else {
        Serial.printf("[MAIN] NTP sync failed (code: %d). TOTP will be inaccurate!\n", ntpResult);
        uiDrawMessage("WARNING", "NTP sync failed!", "TOTP may be wrong.");
        delay(2000);
    }

    // --- 8. Start BLE/FIDO2 Stack ---
    g_state = STATE_INIT_BLE;
    uiDrawInitBLE();

    bleTransportInit(onCtapCommand);
    ctap2Init();
    
    // --- 9. Initialize OTA ---
    otaInit();
    
    // --- 9b. Initialize WiFi Manager ---
    wifiMgrInit();

    delay(500);

    // --- 10. Enter main loop ---
    g_state = STATE_MAIN_UI;
    Serial.println("[MAIN] Entering main loop. Ready.");
}

// =============================================================================
// MAIN LOOP
// =============================================================================

void loop() {
    // --- Run loop tasks ---
    otaLoop();

    // --- Heartbeat LED (Blinks to prove ESP32 is alive, solid if OTA) ---
    static unsigned long lastBlink = 0;
    static bool ledState = false;
    
    if (otaIsUpdating()) {
        digitalWrite(2, HIGH); // Solid ON during OTA
        return;                // Suspend all other logic (UI, TOTP, FIDO, Tunnel) during OTA
    }

    cableTunnelLoop();
    
    if (millis() - lastBlink > 500) {
        lastBlink = millis();
        ledState = !ledState;
        digitalWrite(2, ledState);
    }

    // --- DEBUG: Print raw button states periodically ---
    static unsigned long lastBtnDebug = 0;
    if (millis() - lastBtnDebug > 3000) {
        lastBtnDebug = millis();
        Serial.printf("[DIAG] Raw Pins -> UP(%d): %d | DOWN(%d): %d | APPROVE(%d): %d\n", 
                      PIN_BTN_UP, digitalRead(PIN_BTN_UP),
                      PIN_BTN_DOWN, digitalRead(PIN_BTN_DOWN),
                      PIN_BTN_APPROVE, digitalRead(PIN_BTN_APPROVE));
    }

    // --- Update Buttons ---
    ButtonEvent evt = buttonsUpdate();

    // --- Handle FIDO2 pending requests ---
    FidoPendingRequest* pendingReq = ctap2GetPendingRequest();

    if (pendingReq != nullptr && g_state == STATE_MAIN_UI) {
        if (g_autoAllow) {
            // Auto-approve immediately
            Serial.println("[MAIN] Auto-approving FIDO2 request.");
            ctap2ApproveRequest();
        } else {
            // Switch to prompt state
            if (pendingReq->type == FIDO_REQ_MAKE_CREDENTIAL) {
                g_state = STATE_PROMPT_REGISTER;
            } else {
                g_state = STATE_PROMPT_AUTH;
            }
        }
    }

    // --- State Machine ---
    switch (g_state) {

    case STATE_MAIN_UI: {
        // Only allow page navigation when connectivity page is in overview mode
        bool allowPageNav = true;
        if (g_pageIndex == 4 && wifiMgrGetMode() != CONN_MODE_OVERVIEW) {
            allowPageNav = false;
        }
        
        if (allowPageNav) {
            if (evt == BTN_LEFT_PRESSED) {
                g_pageIndex--;
                if (g_pageIndex < 0) g_pageIndex = TOTAL_PAGES - 1;
            }
            if (evt == BTN_RIGHT_PRESSED) {
                g_pageIndex++;
                if (g_pageIndex >= TOTAL_PAGES) g_pageIndex = 0;
            }
        }

        // Handle page-specific button logic
        if (g_pageIndex == 1) { // TOTP Page
            if (evt == BTN_UP_PRESSED) {
                g_totpIndex--;
                if (g_totpIndex < 0) g_totpIndex = g_totpCount - 1;
            }
            if (evt == BTN_DOWN_PRESSED) {
                g_totpIndex++;
                if (g_totpIndex >= g_totpCount) g_totpIndex = 0;
            }
        } else if (g_pageIndex == 2) { // Settings Page
            if (evt == BTN_UP_PRESSED) {
                g_settingsIndex--;
                if (g_settingsIndex < 0) g_settingsIndex = 2; // Only 3 options now (Auto, IP, MAC)
            }
            if (evt == BTN_DOWN_PRESSED) {
                g_settingsIndex++;
                if (g_settingsIndex > 2) g_settingsIndex = 0;
            }
            if (evt == BTN_APPROVE_SHORT) {
                if (g_settingsIndex == 0) {
                    g_autoAllow = !g_autoAllow;
                    logAdd("Auto-Allow %s", g_autoAllow ? "ON" : "OFF");
                }
            }
        } else if (g_pageIndex == 4) { // Connectivity Page
            ConnPageMode connMode = wifiMgrGetMode();
            
            if (connMode == CONN_MODE_OVERVIEW) {
                int savedCount = wifiMgrSavedCount();
                int totalItems = savedCount + 2; // saved networks + [Scan WiFi] + [BLE]
                
                if (evt == BTN_UP_PRESSED) {
                    g_connIndex--;
                    if (g_connIndex < 0) g_connIndex = totalItems - 1;
                }
                if (evt == BTN_DOWN_PRESSED) {
                    g_connIndex++;
                    if (g_connIndex >= totalItems) g_connIndex = 0;
                }
                if (evt == BTN_APPROVE_SHORT) {
                    if (g_connIndex < savedCount) {
                        // Open sub-menu for this saved network
                        WifiEntry entry;
                        wifiMgrGetSaved(g_connIndex, &entry);
                        wifiMgrSetPendingSSID(entry.ssid);
                        g_savedNetworkIdx = g_connIndex;
                        g_savedMenuIndex = 0;
                        wifiMgrSetMode(CONN_MODE_SAVED_MENU);
                    } else if (g_connIndex == savedCount) {
                        // Scan WiFi
                        wifiMgrSetMode(CONN_MODE_SCANNING);
                        wifiMgrStartScan();
                        g_scanSelIndex = 0;
                    }
                    // BLE item: no action
                }
            }
            else if (connMode == CONN_MODE_SAVED_MENU) {
                // Sub-menu: 0=Connect, 1=Change Password, 2=Forget
                if (evt == BTN_UP_PRESSED) {
                    g_savedMenuIndex--;
                    if (g_savedMenuIndex < 0) g_savedMenuIndex = 2;
                }
                if (evt == BTN_DOWN_PRESSED) {
                    g_savedMenuIndex++;
                    if (g_savedMenuIndex > 2) g_savedMenuIndex = 0;
                }
                if (evt == BTN_APPROVE_SHORT) {
                    if (g_savedMenuIndex == 0) {
                        // Connect
                        wifiMgrSetMode(CONN_MODE_CONNECTING);
                        wifiMgrConnectSaved(g_savedNetworkIdx);
                        wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    } else if (g_savedMenuIndex == 1) {
                        // Change Password — prompt via serial
                        wifiMgrSetMode(CONN_MODE_WAIT_PASSWORD);
                        Serial.println("\n=== CHANGE WIFI PASSWORD ===");
                        Serial.printf("Network: %s\n", wifiMgrGetPendingSSID());
                        Serial.println("Type new password and press Enter:");
                        Serial.print("> ");
                    } else if (g_savedMenuIndex == 2) {
                        // Forget
                        Serial.printf("[WIFIMGR] Forgetting: %s\n", wifiMgrGetPendingSSID());
                        wifiMgrDeleteSaved(g_savedNetworkIdx);
                        g_connIndex = 0;
                        wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    }
                }
                if (evt == BTN_LEFT_PRESSED) {
                    wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    g_pageIndex = 4;
                }
            }
            else if (connMode == CONN_MODE_SCANNING) {
                if (wifiMgrScanDone()) {
                    wifiMgrSetMode(CONN_MODE_SCAN_RESULTS);
                    g_scanSelIndex = 0;
                }
            }
            else if (connMode == CONN_MODE_SCAN_RESULTS) {
                WifiScanResult results[WIFIMGR_MAX_SCAN];
                int count = wifiMgrGetScanResults(results, WIFIMGR_MAX_SCAN);
                
                if (evt == BTN_UP_PRESSED) {
                    g_scanSelIndex--;
                    if (g_scanSelIndex < 0) g_scanSelIndex = count - 1;
                }
                if (evt == BTN_DOWN_PRESSED) {
                    g_scanSelIndex++;
                    if (g_scanSelIndex >= count) g_scanSelIndex = 0;
                }
                if (evt == BTN_APPROVE_SHORT && count > 0) {
                    if (results[g_scanSelIndex].saved) {
                        // Already saved — just connect
                        wifiMgrSetMode(CONN_MODE_CONNECTING);
                        for (int i = 0; i < wifiMgrSavedCount(); i++) {
                            WifiEntry entry;
                            wifiMgrGetSaved(i, &entry);
                            if (strcmp(entry.ssid, results[g_scanSelIndex].ssid) == 0) {
                                wifiMgrConnectSaved(i);
                                break;
                            }
                        }
                        wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    } else if (results[g_scanSelIndex].encrypted) {
                        // Needs password — prompt via serial
                        wifiMgrSetPendingSSID(results[g_scanSelIndex].ssid);
                        wifiMgrSetMode(CONN_MODE_WAIT_PASSWORD);
                        Serial.println("\n=== WIFI PASSWORD REQUIRED ===");
                        Serial.printf("Network: %s\n", results[g_scanSelIndex].ssid);
                        Serial.println("Type password below and press Enter:");
                        Serial.print("> ");
                    } else {
                        // Open network — connect directly
                        wifiMgrSetMode(CONN_MODE_CONNECTING);
                        wifiMgrConnectNew(results[g_scanSelIndex].ssid, "");
                        wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    }
                }
                if (evt == BTN_LEFT_PRESSED) {
                    wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    g_pageIndex = 4; // Stay on page
                }
            }
            else if (connMode == CONN_MODE_WAIT_PASSWORD) {
                char passwordBuf[WIFIMGR_PASS_LEN];
                if (wifiMgrReadSerialLine(passwordBuf, sizeof(passwordBuf))) {
                    Serial.printf("[WIFIMGR] Password received. Connecting to '%s'...\n", wifiMgrGetPendingSSID());
                    wifiMgrSetMode(CONN_MODE_CONNECTING);
                    bool ok = wifiMgrConnectNew(wifiMgrGetPendingSSID(), passwordBuf);
                    if (ok) {
                        Serial.println("[WIFIMGR] SUCCESS! Network saved.");
                    } else {
                        Serial.println("[WIFIMGR] FAILED. Wrong password?");
                    }
                    wifiMgrSetMode(CONN_MODE_OVERVIEW);
                }
                if (evt == BTN_LEFT_PRESSED) {
                    wifiMgrSetMode(CONN_MODE_OVERVIEW);
                    g_pageIndex = 4;
                    Serial.println("[WIFIMGR] Password input cancelled.");
                }
            }
        }

        // Update UI at fixed interval
        if (millis() - g_lastUiUpdate >= UI_REFRESH_MS) {
            g_lastUiUpdate = millis();

            char timeStr[16] = {0};
            getLocalTimeString(timeStr, sizeof(timeStr));
            bool wifiConnected = WiFi.status() == WL_CONNECTED;
            bool bleConnected = bleTransportIsConnected();

            if (g_pageIndex == 0) { // Intro Page
                uiDrawIntroPage(timeStr, wifiConnected, bleConnected, 0, TOTAL_PAGES);
            } 
            else if (g_pageIndex == 1) { // TOTP Page
                TotpAccount account;
                char codeStr[16] = "--- ---";
                uint8_t secsRemaining = 0;
                const char* acctName = "No Accounts";

                if (g_totpCount > 0 && credStoreLoadTotp(g_totpIndex, &account)) {
                    time_t utc = getUTCTimestamp();
                    if (utc > 0) {
                        uint32_t code = totpGenerate(&account, utc);
                        totpFormatCode(code, codeStr, sizeof(codeStr));
                        secsRemaining = totpSecondsRemaining(utc);
                    }
                    acctName = account.name;
                }

                uiDrawTOTP(acctName, codeStr, secsRemaining,
                           g_totpIndex, g_totpCount,
                           g_autoAllow, bleConnected, wifiConnected, timeStr,
                           1, TOTAL_PAGES);
            }
            else if (g_pageIndex == 2) { // Settings Page
                char ipStr[32] = "No WiFi";
                if (wifiConnected) {
                    snprintf(ipStr, sizeof(ipStr), "%s", WiFi.localIP().toString().c_str());
                }
                char macStr[32];
                snprintf(macStr, sizeof(macStr), "%s", WiFi.macAddress().c_str());
                
                uiDrawSettingsMenu(g_settingsIndex, g_autoAllow, ipStr, macStr, 2, TOTAL_PAGES);
            }
            else if (g_pageIndex == 3) { // Logs Page
                uiDrawLogsPage(3, TOTAL_PAGES);
            }
            else if (g_pageIndex == 4) { // Connectivity Page
                ConnPageMode cm = wifiMgrGetMode();
                int selIdx = g_connIndex;
                if (cm == CONN_MODE_SCAN_RESULTS) selIdx = g_scanSelIndex;
                else if (cm == CONN_MODE_SAVED_MENU) selIdx = g_savedMenuIndex;
                uiDrawConnectivityPage(cm, selIdx, 4, TOTAL_PAGES);
            }
        }
        break;
    }

    case STATE_PROMPT_REGISTER:
    case STATE_PROMPT_AUTH: {
        FidoPendingRequest* req = ctap2GetPendingRequest();
        if (req == nullptr) {
            // Request was already processed
            g_state = STATE_MAIN_UI;
            break;
        }

        // Check timeout
        unsigned long elapsed = millis() - req->timestampMs;
        uint8_t timeoutSecs = 0;
        if (elapsed < FIDO2_APPROVAL_TIMEOUT_MS) {
            timeoutSecs = (uint8_t)((FIDO2_APPROVAL_TIMEOUT_MS - elapsed) / 1000);
        } else {
            // Timed out
            Serial.println("[MAIN] FIDO2 request timed out.");
            ctap2DenyRequest();
            g_state = STATE_MAIN_UI;
            break;
        }

        // Handle approve button
        if (evt == BTN_APPROVE_SHORT) {
            Serial.println("[MAIN] User approved FIDO2 request.");
            ctap2ApproveRequest();
            g_state = STATE_MAIN_UI;
            break;
        }

        // Draw prompt
        const char* reqType = (g_state == STATE_PROMPT_REGISTER) ? "Register" : "Login";
        uiDrawFidoPrompt(reqType, req->rpId, g_autoAllow, timeoutSecs);
        break;
    }

    default:
        break;
    }
}
