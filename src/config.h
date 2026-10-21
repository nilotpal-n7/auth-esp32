// =============================================================================
// config.h — hardware pins and compile-time constants
// =============================================================================
#pragma once

#include <Arduino.h>

// WiFi networks and the OTA password come from .env (see .env.example);
// scripts/env_secrets.py generates this header in the build directory.
#include "authkey_secrets.h"

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

// --- Captive portal (IITG FortiGate auto-login) ------------------------------
// Credentials come from .env (IITG_USERNAME / IITG_PASSWORD -> authkey_secrets.h).
#ifndef SECRET_IITG_USER
#define SECRET_IITG_USER ""
#endif
#ifndef SECRET_IITG_PASS
#define SECRET_IITG_PASS ""
#endif
#define PORTAL_HOST             "agnigarh.iitg.ac.in"
#define PORTAL_PORT             1442
#define PORTAL_PROBE_HOST       "detectportal.firefox.com"
#define PORTAL_PROBE_PATH       "/success.txt"
#define PORTAL_PROBE_OK         "success"      // body returned when internet is up
#define PORTAL_PROBE_SECS       120            // re-check internet this often
#define PORTAL_KEEPALIVE_SECS   1200           // refresh the session (< the 1800 s window)
#define PORTAL_RETRY_SECS       30             // retry after a network / unknown failure
#define PORTAL_LIMIT_RETRY_SECS 300            // "session limit": wait for it to free up, retry forever
#define PORTAL_CRED_BACKOFF_SECS 1800          // after repeated rejections (avoids account lockout)
#define PORTAL_MAX_FAILS        3              // rejections before the long back-off

// --- TOTP --------------------------------------------------------------------
#define TOTP_MAX_ACCOUNTS   24

// --- FIDO2 -------------------------------------------------------------------
#define FIDO_MAX_RESIDENT       32      // Discoverable credentials (passkeys)
#define FIDO_MAX_MSG            1024    // Max CTAP request/response size
#define FIDO_USER_TIMEOUT_MS    30000   // Time allowed to press OK
#define FIDO_PIN_MIN_LEN        4
#define FIDO_PIN_MAX_LEN        8
#define FIDO_PIN_MAX_RETRIES    8
