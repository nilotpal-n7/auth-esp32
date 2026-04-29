// =============================================================================
// config.h — ESP32 Hardware Authenticator Configuration
// =============================================================================
#pragma once

#include <Arduino.h>

// =============================================================================
// PIN DEFINITIONS
// =============================================================================

// I2C — OLED Display (SSD1306 128x64)
#define PIN_SDA             21
#define PIN_SCL             22

// Buttons — Active LOW with internal pull-up
#define PIN_BTN_UP          25
#define PIN_BTN_DOWN        26
#define PIN_BTN_APPROVE     27
#define PIN_BTN_LEFT        32
#define PIN_BTN_RIGHT       33

// =============================================================================
// WIFI & NTP CONFIGURATION
// =============================================================================

// >>> ADD YOUR WIFI NETWORKS HERE (up to 5) <<<
// The device will try each network in order and connect to the first one available.
struct WiFiCredential {
    const char* ssid;
    const char* password;
};

const WiFiCredential WIFI_CREDENTIALS[] = {
    { "dance_baby",   "madara_uchiha05"   },
    { "Nilotpal", "dowqqyng0q" },
    // { "Office_WiFi",       "office_pass_123"     },
    // { "Phone_Hotspot",     "hotspot_pass"        },
};
const int WIFI_CREDENTIAL_COUNT = sizeof(WIFI_CREDENTIALS) / sizeof(WIFI_CREDENTIALS[0]);

#define NTP_SERVER          "pool.ntp.org"
#define NTP_GMT_OFFSET      19800       // IST = UTC+5:30 = 19800 seconds
#define NTP_DAYLIGHT_OFFSET 0

#define WIFI_CONNECT_TIMEOUT_MS  8000   // 8 seconds per network
#define NTP_SYNC_TIMEOUT_MS      15000  // 15 seconds (NTP can take a few seconds)

#define ENABLE_OTA          1           // Set to 1 to keep WiFi alive for Over-The-Air updates

// =============================================================================
// TOTP CONFIGURATION
// =============================================================================

#define TOTP_PERIOD         30          // Seconds per TOTP window
#define TOTP_DIGITS         6           // Number of digits in the code
#define TOTP_MAX_ACCOUNTS   20          // Max stored TOTP accounts

// =============================================================================
// FIDO2 / CTAP2 CONFIGURATION
// =============================================================================

#define FIDO2_MAX_CREDENTIALS   200     // Max stored FIDO2 credentials
#define FIDO2_RP_ID_MAX_LEN     64      // Max length of Relying Party ID
#define FIDO2_USER_ID_MAX_LEN   64      // Max length of User ID
#define FIDO2_USER_NAME_MAX_LEN 64      // Max length of User display name
#define FIDO2_CRED_ID_LEN       32      // Credential ID length (random)
#define FIDO2_PRIVKEY_LEN       32      // ECDSA P-256 private key length
#define FIDO2_PUBKEY_LEN        65      // ECDSA P-256 uncompressed public key

// BLE Device identity
#define BLE_DEVICE_NAME     "AuthKey-ESP32"

// FIDO2 approval timeout
#define FIDO2_APPROVAL_TIMEOUT_MS  30000  // 30 seconds

// =============================================================================
// BUTTON CONFIGURATION
// =============================================================================

#define BTN_DEBOUNCE_MS     15          // Debounce interval (ms)
#define BTN_LONG_PRESS_MS   1500        // Long press threshold (ms)

// =============================================================================
// UI CONFIGURATION
// =============================================================================

#define SCREEN_WIDTH        128
#define SCREEN_HEIGHT       64
#define STATUS_BAR_HEIGHT   10
#define NAV_BAR_HEIGHT      11
#define CONTENT_Y_START     (STATUS_BAR_HEIGHT + 2)
#define CONTENT_Y_END       (SCREEN_HEIGHT - NAV_BAR_HEIGHT - 1)

// =============================================================================
// APPLICATION STATE MACHINE
// =============================================================================

enum AppState {
    STATE_BOOT,             // Initial boot, display splash
    STATE_SYNCING_TIME,     // Connecting WiFi + NTP sync
    STATE_INIT_BLE,         // Starting BLE/FIDO2 stack
    STATE_MAIN_UI,          // Paged UI (Intro, TOTP, Settings, Logs)
    STATE_PROMPT_REGISTER,  // FIDO2 MakeCredential prompt
    STATE_PROMPT_AUTH,      // FIDO2 GetAssertion prompt
};

// =============================================================================
// FIDO2 REQUEST TYPES
// =============================================================================

enum FidoRequestType {
    FIDO_REQ_NONE,
    FIDO_REQ_MAKE_CREDENTIAL,
    FIDO_REQ_GET_ASSERTION,
};
