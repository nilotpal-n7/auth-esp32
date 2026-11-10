// =============================================================================
// net/proxmox.h — Proxmox VE API: status, guests, power, backups, updates
//
// Configured in .env per server (PVE_1_HOST = the wake-on-LAN machine's name,
// PVE_1_TOKEN = "user@realm!tokenid=secret"; optional PVE_1_FINGERPRINT and
// PVE_1_NODE). The address comes from the wake-on-LAN machine, so /sethost
// ip also moves the API.
//
// TLS: Proxmox uses a self-signed certificate, so it is PINNED instead of
// chained to a CA: PVE_1_FINGERPRINT (SHA-256, from the Proxmox UI: node →
// System → Certificates) if given, otherwise the certificate seen on the
// first connection (trust on first use, stored in NVS, reported to you so
// you can compare). A different certificate later is refused before the
// token is sent; `pve unpin <machine>` (OK on the device) accepts a renewed one.
//
// Every call blocks for a few seconds (TLS handshake + requests). The Telegram
// connection stays up next to it unless RAM is short.
// =============================================================================
#pragma once

#include <Arduino.h>
#include <time.h>

namespace proxmox {

struct Guest {
    int  vmid;
    char name[24];
    bool lxc;          // container (else VM)
    bool running;
};

void init();
int  count();                       // configured servers
int  find(const char* machine);     // config index for a WoL machine name (or number); -1
int  forHost(int wolIndex);         // config index for a WoL machine index; -1
const char* machine(int c);

// Each returns false with the reason in `out` on failure.
bool summary(int c, String& out);
bool guests(int c, Guest* list, int cap, int* n, String& err);
bool nodePower(int c, const char* command, String& out);            // shutdown | reboot
bool guestPower(int c, int vmid, const char* action, String& out);  // start | shutdown | reboot | stop
// After a maintenance window that began at `since`: backups, updates, restarts.
bool maintenanceReport(int c, time_t since, String& out);

String pinInfo(int c);              // pinned / configured certificate fingerprint
void unpin(int c);                  // accept the next certificate (renewed)

}  // namespace proxmox
