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

// --- Wake-on-LAN servers --------------------------------------------------------
// Machines come from .env (WOL_1_NAME / _MAC / _IP / _PORTS / _BROADCAST,
// WOL_2_..., like the WiFi list) on first boot or `wol reset`, and can be
// added / changed later from Telegram, the web page or the console (kept in
// NVS). Without any in .env, this default is used:
#define WOL_DEFAULT_HOST        {"pve", "64:00:6a:2b:36:9f", "172.16.114.175", "8006,22", "172.16.119.255"}
#define WOL_MAX_HOSTS           8
#define WOL_UDP_PORT            9
#define WOL_CONNECT_TIMEOUT_MS  1500               // per port: a check blocks at most ~3 s
#define WOL_PACKETS             3                  // magic packets per wake, 1 s apart
#define WOL_WATCH_SECS          180                // after a wake: report when it is up
#define WOL_WATCH_EVERY_SECS    10
#define WOL_AUTO_CHECK_SECS     60                 // auto-wake: how often each host is looked at
#define WOL_AUTO_DEFAULT_MIN    10                 // auto-wake: down this long -> wake
#define WOL_AUTO_MAX_TRIES      3                  // then wait until it is seen up again

// --- Telegram bot ------------------------------------------------------------
// Token and allowed chat IDs come from .env (TELEGRAM_BOT_TOKEN / _CHAT_ID).
#ifndef SECRET_TG_TOKEN
#define SECRET_TG_TOKEN ""
#endif
#ifndef SECRET_TG_CHATS
#define SECRET_TG_CHATS ""
#endif
#define TG_HOST                 "api.telegram.org"
#define TG_LONG_POLL_SECS       25                 // Telegram holds getUpdates open this long
#define TG_MAX_COMMAND_AGE_SECS 120                // older commands (queued while off) are ignored
#define TG_BACKOFF_MIN_SECS     5
#define TG_BACKOFF_MAX_SECS     120
#define TG_MIN_HEAP             20000              // largest free block: TLS allocates 16 KB record buffers
#define TG_MIN_FREE_HEAP        62000              // total free heap needed (TLS peaks at ~54 KB)

// --- Watchdog ----------------------------------------------------------------
// The longest legitimate stall in loop() is a TLS handshake or a WiFi
// reconnect (~10-15 s); OTA resets the watchdog from its progress callback.
#define LOOP_WATCHDOG_SECS      60

// --- TOTP --------------------------------------------------------------------
#define TOTP_MAX_ACCOUNTS   24

// --- FIDO2 -------------------------------------------------------------------
#define FIDO_MAX_RESIDENT       32      // Discoverable credentials (passkeys)
#define FIDO_MAX_MSG            1024    // Max CTAP request/response size
#define FIDO_USER_TIMEOUT_MS    30000   // Time allowed to press OK
#define FIDO_PIN_MIN_LEN        4
#define FIDO_PIN_MAX_LEN        8
#define FIDO_PIN_MAX_RETRIES    8
