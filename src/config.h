// =============================================================================
// config.h — hardware pins and compile-time constants
// =============================================================================
#pragma once

#include <Arduino.h>

#if __has_include("secrets.h")
#include "secrets.h"
#else
#warning "src/secrets.h not found - copy src/secrets.example.h to src/secrets.h"
#define SECRET_WIFI_NETWORKS
#define SECRET_OTA_PASSWORD ""
#endif

#define FW_NAME     "AuthKey-ESP32"
#define FW_VERSION  "2.0.0"

// --- Pins --------------------------------------------------------------------
#define PIN_SDA         21
#define PIN_SCL         22
#define PIN_LED         2

// Buttons are active LOW with internal pull-ups. UP / DOWN / OK are required;
// LEFT / RIGHT are optional shortcuts (back / forward) and may be left
// unconnected.
#define PIN_BTN_UP      25
#define PIN_BTN_DOWN    26
#define PIN_BTN_OK      27
#define PIN_BTN_LEFT    32
#define PIN_BTN_RIGHT   33

#define BTN_DEBOUNCE_MS     15
#define BTN_LONG_PRESS_MS   700

// --- Display -----------------------------------------------------------------
// Most 0.96" modules are SSD1306; many 1.3" modules are SH1106.
#define OLED_DRIVER_SSD1306 1
#define OLED_DRIVER_SH1106  2
#define OLED_DRIVER         OLED_DRIVER_SSD1306
#define DISPLAY_SLEEP_MS    60000   // Dim after inactivity (0 = never)

// --- Time --------------------------------------------------------------------
// POSIX TZ string used for the on-screen clock only. TOTP always uses UTC.
// Can be changed at runtime with the `tz` console command.
#define DEFAULT_TZ          "IST-5:30"
#define NTP_SERVER_1        "pool.ntp.org"
#define NTP_SERVER_2        "time.google.com"

// --- WiFi --------------------------------------------------------------------
#define WIFI_MAX_SAVED          8
#define WIFI_CONNECT_TIMEOUT_MS 10000

// --- TOTP --------------------------------------------------------------------
#define TOTP_MAX_ACCOUNTS   24

// --- FIDO2 -------------------------------------------------------------------
#define FIDO_MAX_RESIDENT       32      // Discoverable credentials (passkeys)
#define FIDO_MAX_MSG            1024    // Max CTAP request/response size
#define FIDO_USER_TIMEOUT_MS    30000   // Time allowed to press OK
#define FIDO_PIN_MIN_LEN        4
#define FIDO_PIN_MAX_LEN        8
#define FIDO_PIN_MAX_RETRIES    8
