// =============================================================================
// net/wol.h — wake machines on the LAN and watch whether they are up
//
// Up to WOL_MAX_HOSTS machines (kept in NVS; seeded from .env or config.h):
//   name, MAC, IP (optional: only for status checks), TCP ports to check,
//   optional directed broadcast, per-host auto-wake, alerts and maintenance
//   windows. One global switch turns the whole feature off.
//
//   wake():  6x 0xFF + 16x MAC over UDP port 9 to 255.255.255.255, the host's
//            broadcast and the current subnet's broadcast; WOL_PACKETS times,
//            1 s apart (non-blocking). Then checks every 10 s for 3 min and
//            reports when the machine is up (or that it didn't come up).
//   check(): TCP connect to the host's ports in turn (Proxmox: 8006, then 22);
//            more reliable than ping. Blocks at most ~1.5 s per port.
//   Monitor: every machine with an IP is checked about once a minute.
//            - Alerts: "went down" after 2 failed checks in a row, "back up"
//              on the next success (only changes, never at boot).
//            - Auto-wake: unreachable for N minutes -> magic packet (at most
//              3 tries until it is seen up again).
//            - Pause: both of the above off until a time, or "until it is
//              seen up" (set after a deliberate shutdown).
//            - Maintenance windows (weekly, e.g. Sat 00:00 for 120 min): the
//              machine is woken a few minutes before if it is off, so
//              scheduled updates / backups run; restarts inside the window
//              don't alert; a summary is sent when the window ends.
//
// Reports go to the notifier (the Telegram bot) and the event log.
// =============================================================================
#pragma once

#include <Arduino.h>
#include <time.h>
#include "config.h"

namespace wol {

#define WOL_PAUSE_UNTIL_UP 0xFFFFFFFFu
#define WOL_MAINT_SLOTS    2

// Weekly window: `days` bit 0 = Sunday .. bit 6 = Saturday (0 = unused).
struct Window {
    uint8_t  days;
    uint8_t  hour, minute;
    uint8_t  reserved;
    uint16_t minutes;
};

struct Host {
    char     name[16];
    uint8_t  mac[6];
    char     ip[16];          // "" = unknown (no status checks / auto-wake)
    uint16_t ports[2];        // checked in order; 0 = unused
    char     broadcast[16];   // "" = subnet broadcast only
    bool     autoWake;
    uint16_t autoMin;
    // Added in 2.1 (older records are migrated with the defaults below).
    bool     alerts;          // down / up notifications (default on)
    bool     maintWake;       // wake before a maintenance window (default on)
    uint32_t pausedUntil;     // UTC; 0 = not paused; WOL_PAUSE_UNTIL_UP
    Window   maint[WOL_MAINT_SLOTS];
};

void init();
void loop();

typedef void (*NotifyFn)(const char* text);
void setNotifier(NotifyFn fn);          // results of actions (always sent)
void setAlertNotifier(NotifyFn fn);     // down / up / maintenance alerts (may be muted)
// Called when a maintenance window ends with the summary text. Return true to
// take over sending it (the bot adds Proxmox details), false to send as is.
typedef bool (*MaintEndFn)(int host, const char* summary, time_t windowStart);
void setMaintEndHandler(MaintEndFn fn);

// --- Hosts ---
int  count();
const Host* host(int i);
int  find(const char* nameOrNumber);       // name (case-insensitive) or 1-based number; -1 if none
// Adds or replaces (same name). Fills `err` on failure. Returns the index or -1.
int  put(const Host& h, char* err, size_t errCap);
bool remove(int i);
void resetToDefaults();                     // re-import .env / config.h
// Parses "11:22:33:44:55:66" (or '-' separated / no separators).
bool parseMac(const char* s, uint8_t mac[6]);
void formatMac(const uint8_t mac[6], char* out, size_t cap);
// Fills a Host from text fields (validated). ports e.g. "8006,22".
bool makeHost(const char* name, const char* mac, const char* ip, const char* ports,
              const char* broadcast, Host* out, char* err, size_t errCap);
// Keeps the settings (auto-wake, alerts, pause, windows) of `from` in `to`.
void copySettings(const Host& from, Host* to);

// --- Global switch ---
bool enabled();
void setEnabled(bool on);

// --- Actions ---
bool wake(int i, const char* why);          // false: feature off / bad index
bool waking(int i);
// Blocking reachability check. `port` = the port that answered (0 = down).
bool check(int i, uint16_t* port = nullptr, uint32_t* ms = nullptr);
int  lastState(int i);                      // -1 unknown, 0 down, 1 up
uint32_t lastCheckAgeS(int i);              // seconds since the last check (UINT32_MAX = never)
time_t stateSince(int i);                   // UTC of the last up/down change (0 = unknown)
void setAutoWake(int i, bool on, int minutes = 0);   // minutes 0 = keep
void setAlerts(int i, bool on);

// --- Pause (auto-wake and alerts) ---
// seconds > 0: for that long; 0: resume; WOL_PAUSE_UNTIL_UP: until seen up.
bool pause(int i, uint32_t seconds);
bool paused(int i);
// Deliberate shutdown (e.g. Proxmox from Telegram): pause until it is seen
// up again and report once it is off.
void expectShutdown(int i, const char* why);
// Deliberate reboot: no "down" alert; reports when it is back (or that it
// didn't come back within WOL_RESTART_WAIT_MIN).
void expectRestart(int i);

// --- Maintenance windows ---
// "sat 00:00 120", "sat,sun 0:30 90", "daily 03:00 60". Fills `err`.
bool parseWindow(const char* text, Window* out, char* err, size_t errCap);
void formatWindow(const Window& w, char* out, size_t cap);   // "Sat 00:00, 120 min"
bool addWindow(int i, const Window& w, char* err, size_t errCap);
void clearWindows(int i);
void setMaintWake(int i, bool on);
bool inMaintenance(int i);
// Next window start (UTC) for host i, 0 if none / clock not set.
time_t nextWindow(int i);
// Parses "2h", "30m", "1d", "90" (minutes). 0 on error.
uint32_t parseDuration(const char* s);

}  // namespace wol
