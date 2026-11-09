// =============================================================================
// net/wol.h — wake machines on the LAN and watch whether they are up
//
// Up to WOL_MAX_HOSTS machines (kept in NVS; seeded from .env or config.h):
//   name, MAC, IP (optional: only for status checks), TCP ports to check,
//   optional directed broadcast, and a per-host auto-wake switch + minutes.
// One global switch turns the whole feature off (no packets, no auto-wake).
//
//   wake():  6x 0xFF + 16x MAC over UDP port 9 to 255.255.255.255, the host's
//            broadcast and the current subnet's broadcast; WOL_PACKETS times,
//            1 s apart (non-blocking). Then checks every 10 s for 3 min and
//            reports when the machine is up (or that it didn't come up).
//   check(): TCP connect to the host's ports in turn (Proxmox: 8006, then 22);
//            more reliable than ping. Blocks at most ~1.5 s per port.
//   Auto-wake: if a host with auto-wake on is unreachable for N minutes,
//            send the packet and report it (at most 3 tries until seen up).
//
// Reports go to the notifier (the Telegram bot) and the event log.
// =============================================================================
#pragma once

#include <Arduino.h>
#include "config.h"

namespace wol {

struct Host {
    char     name[16];
    uint8_t  mac[6];
    char     ip[16];          // "" = unknown (no status checks / auto-wake)
    uint16_t ports[2];        // checked in order; 0 = unused
    char     broadcast[16];   // "" = subnet broadcast only
    bool     autoWake;
    uint16_t autoMin;
};

void init();
void loop();

typedef void (*NotifyFn)(const char* text);
void setNotifier(NotifyFn fn);

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
void setAutoWake(int i, bool on, int minutes = 0);   // minutes 0 = keep

}  // namespace wol
