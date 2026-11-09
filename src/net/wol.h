// =============================================================================
// net/wol.h — wake the Proxmox server over the LAN and watch whether it is up
//
//   wake():  6x 0xFF + 16x MAC over UDP port 9 to 255.255.255.255, the
//            configured directed broadcast and the current subnet's
//            broadcast; WOL_PACKETS times, 1 s apart (non-blocking). Then it
//            checks every 10 s for 3 min and reports when the server is up.
//   check(): TCP connect to the Proxmox UI (8006), falling back to SSH (22);
//            more reliable than ping. Blocks at most ~3 s.
//   Auto-wake (off by default, kept in NVS): if the server has been
//            unreachable for N minutes, send the packet and report it.
//
// Reports go to whoever registered with setNotifier() (the Telegram bot) and
// to the event log.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace wol {

void init();
void loop();

typedef void (*NotifyFn)(const char* text);
void setNotifier(NotifyFn fn);

// Starts sending the magic packets (and the 3-minute watch). `why` is shown
// in reports, e.g. "/wake" or "auto-wake".
void wake(const char* why);
bool waking();                     // packets still going out or watching

// Blocking reachability check. `port` = the port that answered (0 = down).
bool check(uint16_t* port = nullptr, uint32_t* ms = nullptr);

const char* serverIp();
bool setServerIp(const char* ip);  // validated, saved in NVS

bool autoWake();
int  autoWakeMinutes();
void setAutoWake(bool on, int minutes = 0);   // minutes 0 = keep the current value

// Last known state from any check: -1 unknown, 0 down, 1 up.
int  lastState();

}  // namespace wol
