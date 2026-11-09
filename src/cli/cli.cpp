#include "cli/cli.h"
#include "config.h"
#include "core/approval.h"
#include "core/backup.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "fido/credentials.h"
#include "fido/ctap2.h"
#include "net/network.h"
#include "net/portal.h"
#include "net/proxmox.h"
#include "net/telegram.h"
#include "net/wol.h"
#include "totp/totp.h"
#include "transport/ble.h"
#include "transport/hybrid.h"
#include "util/codec.h"
#include "unlock/unlock.h"

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "net/tunnel_ca.h"
#include <mbedtls/x509_crt.h>

namespace cli {

static char   s_line[2 * FIDO_MAX_MSG + 64];
static size_t s_len = 0;

#define MAX_ARGS 7

// Split into arguments; "double quotes" group words. Modifies `line`.
static int tokenize(char* line, char** argv) {
    int argc = 0;
    char* p = line;
    while (*p && argc < MAX_ARGS) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '"') {
            argv[argc++] = ++p;
            while (*p && *p != '"') p++;
        } else {
            argv[argc++] = p;
            // The last argument keeps the rest of the line (e.g. passwords with spaces).
            if (argc == MAX_ARGS) break;
            while (*p && *p != ' ') p++;
        }
        if (*p) *p++ = '\0';
    }
    return argc;
}

static void help() {
    consoleWrite(
        "Commands:\n"
        "  status                      device overview\n"
        "  totp list                   list accounts\n"
        "  totp add <name> <base32>    add account (quote names with spaces)\n"
        "  totp uri <otpauth://...>    add account from an otpauth URI\n"
        "  totp del <n>                delete account n\n"
#ifdef AUTHKEY_TEST_HOOKS
        "  totp code <n> [unix]        print a code (test build only)\n"
        "  approve | deny | uvpin <pin> | setpin <pin> | clearpin   (test build only)\n"
#endif
        "  wifi list | wifi add <ssid> <password> | wifi del <n>\n"
        "  portal status|on|off|login|logout   IITG captive-portal auto-login\n"
        "  wol [list] | wol add <name> <mac> [ip|-] [ports] [broadcast] | wol del <host>\n"
        "  wol wake|check <host> | wol auto <host> on|off [min] | wol on|off | wol reset   wake-on-LAN\n"
        "  wol alerts <host> on|off | wol pause <host> <2h|up|off> | wol maint <host> [add sat 00:00 120|clear|wake on|off]\n"
        "  pve [machine] | pve guests [machine] | pve cert [machine] | pve unpin <machine>   Proxmox API\n"
        "  tg | tg ping | tg sim <text>   bot status | test TLS | run a bot command here\n"
        "  wifi connect | wifi reset   reconnect | restore the .env list\n"
        "  time | time set <unix>      show / set UTC clock\n"
        "  tz <POSIX TZ>               clock timezone, e.g. IST-5:30, CET-1CEST,M3.5.0,M10.5.0/3\n"
        "  passkeys | passkey del <n>  list / delete discoverable credentials\n"
        "  unlock list | unlock remove <n>   PCs paired for Windows sign-in\n"
        "  pin                         device PIN status (set it on the device)\n"
        "  lock | uvhours <n>          end the unlocked-PIN session | its length (0 = until reboot)\n"
        "  auto on|off                 hands-free sign-in + registration (PIN once per unlocked session)\n"
        "  hybrid <FIDO:/...> | hybrid stop   phone-style login from a QR string\n"
        "  bt forget                   remove all Bluetooth bonds\n"
        "  log | log clear             recent events (kept across reboots)\n"
        "  kbd | kbd on|off | kbd type <n>   Bluetooth keyboard (types TOTP codes)\n"
        "  backup | restore            use tools/authkey.py backup|restore <file>\n"
        "  ctap <hex>                  raw CTAP2 request (test harness)\n"
        "  reboot\n");
}

static void status() {
    char clock[8];
    network::localClock(clock, sizeof(clock));
    consolef("%s v%s\n", FW_NAME, FW_VERSION);
    consolef("  WiFi:      %s %s\n", network::connected() ? network::ssid() : "not connected",
             network::ip().c_str());
    consolef("  Clock:     %s (%s), UTC %ld\n", network::timeValid() ? clock : "not set",
             settings::timezone(), (long)network::now());
    consolef("  Bluetooth: %d link(s), %d bond(s), keyboard %s (%d host(s)), MAC %s\n",
             ble::linkCount(), ble::bondCount(), ble::keyboardEnabled() ? "on" : "off",
             ble::keyboardHosts(), WiFi.macAddress().c_str());
    if (network::connected()) consolef("  Web page:  http://%s/\n", network::ip().c_str());
    consolef("  TOTP:      %d account(s)\n", totp::count());
    consolef("  Passkeys:  %d/%d discoverable, sign count %lu\n", creds::residentCount(),
             creds::residentCapacity(), (unsigned long)settings::signCount());
    consolef("  PIN:       %s, auto-approve %s\n",
             settings::pinIsSet() ? "set" : "not set", settings::autoApprove() ? "ON" : "off");
    uint32_t left = settings::uvSessionMinutesLeft();
    if (left == UINT32_MAX) consoleWrite("  Session:   unlocked until reboot\n");
    else if (left) consolef("  Session:   unlocked, %lu min left\n", (unsigned long)left);
    else consoleWrite("  Session:   locked (next verified request asks for the PIN)\n");
    consolef("  Hybrid:    %s\n", hybrid::stateText());
    consolef("  OTA:       %s\n", network::otaEnabled() ? "enabled" : "disabled (no password)");
    if (portal::haveCredentials()) {
        consolef("  Portal:    %s (%s), auto %s, %s\n", portal::stateStr(), portal::user(),
                 portal::enabled() ? "on" : "off", portal::lastResult());
    }
    consolef("  Servers:   %d, wake-on-LAN %s, %d Proxmox\n", wol::count(), wol::enabled() ? "on" : "off", proxmox::count());
    char bk[64];
    backup::describe(bk, sizeof(bk));
    consolef("  Backup:    %s\n", bk);
    consolef("  Telegram:  %s%s%s\n", telegram::stateStr(), telegram::lastError()[0] ? ", " : "",
             telegram::lastError());
    consolef("  Heap:      %u free, largest block %u\n", (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
}

static void cmdTotp(int argc, char** argv) {
    const char* sub = argc > 1 ? argv[1] : "list";
    if (!strcmp(sub, "list")) {
        TotpAccount a;
        for (int i = 0; i < totp::count(); i++) {
            if (!totp::get(i, &a)) continue;
            consolef("  %d: %s (%d digits, %ds, %s)\n", i, a.name, a.digits, a.period,
                     a.algo == 1 ? "SHA1" : a.algo == 256 ? "SHA256" : "SHA512");
        }
        if (!totp::count()) consoleWrite("  (none)\n");
        crypto::wipe(&a, sizeof(a));
    } else if (!strcmp(sub, "add") && argc >= 4) {
        TotpAccount a;
        if (!totp::fromBase32(argv[2], argv[3], &a)) { consoleWrite("ERR invalid base32 secret\n"); return; }
        int i = totp::add(a);
        crypto::wipe(&a, sizeof(a));
        if (i < 0) consoleWrite("ERR storage full\n");
        else { consolef("OK added #%d\n", i); logEvent("TOTP added"); }
    } else if (!strcmp(sub, "uri") && argc >= 3) {
        TotpAccount a;
        if (!totp::parseUri(argv[2], &a)) { consoleWrite("ERR invalid otpauth URI\n"); return; }
        int i = totp::add(a);
        crypto::wipe(&a, sizeof(a));
        if (i < 0) consoleWrite("ERR storage full\n");
        else { consolef("OK added #%d\n", i); logEvent("TOTP added"); }
    } else if (!strcmp(sub, "del") && argc >= 3) {
        consoleWrite(totp::remove(atoi(argv[2])) ? "OK\n" : "ERR no such account\n");
#ifdef AUTHKEY_TEST_HOOKS
    } else if (!strcmp(sub, "code") && argc >= 3) {
        TotpAccount a;
        if (!totp::get(atoi(argv[2]), &a)) { consoleWrite("ERR no such account\n"); return; }
        time_t t = argc >= 4 ? (time_t)strtoll(argv[3], nullptr, 10) : network::now();
        if (!t) { consoleWrite("ERR clock not set\n"); return; }
        char code[12];
        snprintf(code, sizeof(code), "%0*lu", a.digits, (unsigned long)totp::generate(a, t));
        crypto::wipe(&a, sizeof(a));
        consolef("CODE %s\n", code);
#endif
    } else {
        consoleWrite("ERR usage: totp list|add|uri|del\n");
    }
}

static void cmdWifi(int argc, char** argv) {
    const char* sub = argc > 1 ? argv[1] : "list";
    if (!strcmp(sub, "list")) {
        char ssid[33];
        for (int i = 0; i < network::savedCount(); i++) {
            network::savedSsid(i, ssid, sizeof(ssid));
            consolef("  %d: %s%s\n", i, ssid, !strcmp(ssid, network::ssid()) ? "  (connected)" : "");
        }
        if (!network::savedCount()) consoleWrite("  (none)\n");
    } else if (!strcmp(sub, "add") && argc >= 3) {
        consoleWrite(network::savedAdd(argv[2], argc >= 4 ? argv[3] : "") ? "OK saved\n" : "ERR\n");
    } else if (!strcmp(sub, "del") && argc >= 3) {
        consoleWrite(network::savedRemove(atoi(argv[2])) ? "OK\n" : "ERR no such network\n");
    } else if (!strcmp(sub, "reset")) {
        network::savedResetToDefaults();
        consoleWrite("OK\n");
    } else if (!strcmp(sub, "connect")) {
        consoleWrite(network::ensureConnected() ? "OK connected\n" : "ERR could not connect\n");
    } else {
        consoleWrite("ERR usage: wifi list|add|del|connect|reset\n");
    }
}

static void cmdPortal(int argc, char** argv) {
    const char* sub = argc > 1 ? argv[1] : "status";
    if (!strcmp(sub, "status")) {
        if (!portal::haveCredentials()) { consoleWrite("  no IITG credentials in .env\n"); return; }
        consolef("  state:    %s%s\n", portal::stateStr(), portal::paused() ? " (paused)" : "");
        consolef("  user:     %s, auto-login %s\n", portal::user(), portal::enabled() ? "on" : "off");
        consolef("  last:     %s\n", portal::lastResult());
        consolef("  session:  %s, next %s in %lus\n", portal::ownsSession() ? "ours" : "not ours",
                 portal::ownsSession() && portal::online() ? "refresh" : "check",
                 (unsigned long)portal::secondsToNext());
        consolef("  counters: %d login(s), %d refresh(es)\n", portal::logins(), portal::keepalives());
    } else if (!strcmp(sub, "on")) {
        portal::setEnabled(true);  consoleWrite("OK auto-login on\n");
    } else if (!strcmp(sub, "off")) {
        portal::setEnabled(false); consoleWrite("OK auto-login off\n");
    } else if (!strcmp(sub, "login")) {
        portal::loginNow();        consoleWrite("OK logging in (see `portal` / `log`)\n");
    } else if (!strcmp(sub, "logout")) {
        portal::logout();          consoleWrite("OK logging out; auto-login paused until `portal login`\n");
    } else {
        consoleWrite("ERR usage: portal status|on|off|login|logout\n");
    }
}

// --- Server wake-on-LAN ---------------------------------------------------------
static const char* stateWord(int i) {
    int st = wol::lastState(i);
    return wol::waking(i) ? "waking" : st < 0 ? "?" : st ? "up" : "down";
}

static void listHosts() {
    char mac[18];
    for (int i = 0; i < wol::count(); i++) {
        const wol::Host* h = wol::host(i);
        wol::formatMac(h->mac, mac, sizeof(mac));
        consolef("  %d: %-10s %s  %-15s ports %u,%u  %-6s auto-wake %s%s\n", i + 1, h->name, mac,
                 h->ip[0] ? h->ip : "(no IP)", h->ports[0], h->ports[1], stateWord(i),
                 h->autoWake ? "on " : "off", h->autoWake ? (String("(") + h->autoMin + " min)").c_str() : "");
    }
    for (int i = 0; i < wol::count(); i++) {
        const wol::Host* h = wol::host(i);
        char w[40];
        String extra;
        if (!h->alerts) extra += " alerts off";
        if (wol::paused(i)) extra += h->pausedUntil == WOL_PAUSE_UNTIL_UP ? " paused-until-up" : " paused";
        for (const wol::Window& win : h->maint) {
            if (!win.days) continue;
            wol::formatWindow(win, w, sizeof(w));
            extra += String(" maint[") + w + "]";
        }
        if (h->maint[0].days || h->maint[1].days) extra += h->maintWake ? " wake-before" : " no-wake-before";
        if (wol::inMaintenance(i)) extra += " IN-WINDOW";
        if (extra.length()) consolef("     %s:%s\n", h->name, extra.c_str());
    }
    if (!wol::count()) consoleWrite("  (no machines: wol add <name> <mac> [ip] [ports] [broadcast])\n");
}

// wol | wol list | wol add <name> <mac> [ip|-] [ports] [broadcast] | wol del <host>
// wol wake <host> | wol check <host> | wol auto <host> on|off [min] | wol on|off | wol reset
static void cmdWol(int argc, char** argv) {
    const char* sub = argc > 1 ? argv[1] : "list";
    if (!strcmp(sub, "list")) {
        consolef("  wake-on-LAN %s\n", wol::enabled() ? "on" : "OFF (wol on to enable)");
        listHosts();
    } else if (!strcmp(sub, "on") || !strcmp(sub, "off")) {
        wol::setEnabled(!strcmp(sub, "on"));
        logEvent("WoL %s", wol::enabled() ? "on" : "off");
        consolef("OK wake-on-LAN %s\n", wol::enabled() ? "on" : "off");
    } else if (!strcmp(sub, "reset")) {
        wol::resetToDefaults();
        consoleWrite("OK machines reset to the .env / built-in list\n");
        listHosts();
    } else if (!strcmp(sub, "add") && argc >= 4) {
        // The last argument may hold "ports broadcast" together (tokenizer keeps the rest).
        char rest[48] = "";
        char* ports = nullptr;
        char* bcast = nullptr;
        if (argc >= 6) {
            strlcpy(rest, argv[5], sizeof(rest));
            ports = strtok(rest, " ");
            bcast = strtok(nullptr, " ");
        }
        wol::Host h;
        char err[64];
        if (!wol::makeHost(argv[2], argv[3], argc >= 5 ? argv[4] : "", ports, bcast, &h, err, sizeof(err))) {
            consolef("ERR %s\n", err);
            return;
        }
        int i = wol::put(h, err, sizeof(err));
        if (i < 0) consolef("ERR %s\n", err);
        else { consolef("OK %s saved as #%d\n", h.name, i + 1); logEvent("WoL host %s saved", h.name); }
    } else if (argc >= 3 && (!strcmp(sub, "alerts") || !strcmp(sub, "pause") || !strcmp(sub, "maint"))) {
        int i = wol::find(argv[2]);
        if (i < 0) { consolef("ERR no machine '%s' (wol list)\n", argv[2]); return; }
        const char* arg = argc >= 4 ? argv[3] : "";
        char err[64];
        if (!strcmp(sub, "alerts")) {
            wol::setAlerts(i, !strcmp(arg, "on"));
            consolef("OK %s alerts %s\n", wol::host(i)->name, wol::host(i)->alerts ? "on" : "off");
        } else if (!strcmp(sub, "pause")) {
            uint32_t secs = !strcmp(arg, "off") ? 0 : !strcmp(arg, "up") ? WOL_PAUSE_UNTIL_UP : wol::parseDuration(arg);
            if (strcmp(arg, "off") && !secs) { consoleWrite("ERR usage: wol pause <host> 2h|30m|up|off\n"); return; }
            if (!wol::pause(i, secs)) { consoleWrite("ERR the clock isn't set (use: up)\n"); return; }
            consolef("OK %s %s\n", wol::host(i)->name, wol::paused(i) ? "paused" : "resumed");
        } else {
            // The tokenizer split "add sat 00:00 120": join it again.
            char rest[64] = "";
            for (int k = 3; k < argc; k++) {
                if (k > 3) strlcat(rest, " ", sizeof(rest));
                strlcat(rest, argv[k], sizeof(rest));
            }
            char* verb = strtok(rest, " ");
            char* tail = strtok(nullptr, "");
            wol::Window w;
            if (verb && !strcmp(verb, "add")) {
                if (!wol::parseWindow(tail, &w, err, sizeof(err)) || !wol::addWindow(i, w, err, sizeof(err))) {
                    consolef("ERR %s\n", err);
                    return;
                }
            } else if (verb && !strcmp(verb, "clear")) {
                wol::clearWindows(i);
            } else if (verb && !strcmp(verb, "wake") && tail) {
                wol::setMaintWake(i, !strcmp(tail, "on"));
            } else if (verb) {
                consoleWrite("ERR usage: wol maint <host> add <days> <HH:MM> <min> | clear | wake on|off\n");
                return;
            }
            listHosts();
        }
    } else if (argc >= 3 && (!strcmp(sub, "del") || !strcmp(sub, "wake") || !strcmp(sub, "check") ||
                             !strcmp(sub, "auto"))) {
        int i = wol::find(argv[2]);
        if (i < 0) { consolef("ERR no machine '%s' (wol list)\n", argv[2]); return; }
        const char* name = wol::host(i)->name;
        if (!strcmp(sub, "del")) {
            char n[16];
            strlcpy(n, name, sizeof(n));
            wol::remove(i);
            logEvent("WoL host %s removed", n);
            consolef("OK %s removed\n", n);
        } else if (!strcmp(sub, "wake")) {
            if (wol::wake(i, "console")) consolef("OK waking %s (3 packets, 1 s apart; watching 3 min)\n", name);
            else consoleWrite("ERR wake-on-LAN is off (wol on)\n");
        } else if (!strcmp(sub, "check")) {
            uint16_t port;
            uint32_t ms = 0;
            if (!wol::host(i)->ip[0]) consolef("ERR %s has no IP set\n", name);
            else if (wol::check(i, &port, &ms)) consolef("UP %s (%s) answers on port %u (%lu ms)\n", name, wol::host(i)->ip, port, (unsigned long)ms);
            else consolef("DOWN %s (%s): no answer on %u/%u\n", name, wol::host(i)->ip, wol::host(i)->ports[0], wol::host(i)->ports[1]);
        } else if (argc >= 4) {
            wol::setAutoWake(i, !strcmp(argv[3], "on"), argc >= 5 ? atoi(argv[4]) : 0);
            consolef("OK %s auto-wake %s (%d min)\n", name, wol::host(i)->autoWake ? "on" : "off", wol::host(i)->autoMin);
        } else {
            consoleWrite("ERR usage: wol auto <host> on|off [minutes]\n");
        }
    } else {
        consoleWrite("ERR usage: wol [list] | add <name> <mac> [ip|-] [ports] [broadcast] | del|wake|check <host> |"
                     " auto <host> on|off [min] | on | off | reset\n");
    }
}

// pve [machine] | pve guests [machine] | pve cert [machine] | pve unpin <machine>
static void cmdPve(int argc, char** argv) {
    const char* sub = argc > 1 ? argv[1] : "";
    bool verb = !strcmp(sub, "guests") || !strcmp(sub, "cert") || !strcmp(sub, "unpin");
    const char* who = verb ? (argc > 2 ? argv[2] : "") : sub;
    int c = proxmox::find(who);
    if (c < 0) {
        consolef("ERR %s\n", proxmox::count() ? "no such Proxmox server" : "no Proxmox server in .env (PROXMOX_TOKEN_ID, PROXMOX_TOKEN)");
        return;
    }
    String out;
    if (!strcmp(sub, "cert")) {
        consolef("%s certificate: %s\n", proxmox::machine(c), proxmox::pinInfo(c).c_str());
    } else if (!strcmp(sub, "unpin")) {
        proxmox::unpin(c);
        consolef("OK %s: the next certificate seen is pinned\n", proxmox::machine(c));
    } else if (!strcmp(sub, "guests")) {
        static proxmox::Guest g[24];
        int n = 0;
        bool ok = proxmox::guests(c, g, 24, &n, out);
        for (int i = 0; i < n; i++) consolef("  %d %-20s %s %s\n", g[i].vmid, g[i].name, g[i].lxc ? "CT" : "VM", g[i].running ? "running" : "stopped");
        if (!ok || out.length()) consolef("%s %s\n", ok ? "WARN" : "ERR", out.c_str());
    } else {
        bool ok = proxmox::summary(c, out);
        consoleWrite(out.c_str());
        consoleWrite(ok ? "\n" : "\nERR\n");
    }
}

static void cmdTelegram(int argc, char** argv) {
    if (argc >= 3 && !strcmp(argv[1], "sim")) {
        String text;                       // the tokenizer split the command: join it again
        for (int i = 2; i < argc; i++) { if (i > 2) text += ' '; text += argv[i]; }
        telegram::simulate(text.c_str());
        return;
    }
    if (argc >= 2 && !strcmp(argv[1], "ping")) {
        char out[160];
        bool ok = telegram::ping(out, sizeof(out));
        consolef("%s %s\n", ok ? "OK" : "ERR", out);
        return;
    }
    consolef("  bot:       %s\n", telegram::stateStr());
    if (telegram::lastError()[0]) consolef("  last error: %s\n", telegram::lastError());
    if (telegram::lastIgnoredChat()) consolef("  last ignored chat: %lld\n", telegram::lastIgnoredChat());
}

// --- PC unlock (Windows sign-in) -------------------------------------------
static void serialUnlockReply(bool ok, const uint8_t* mac, void* ctx) {
    bool pairing = ctx != nullptr;
    if (!ok) { consoleWrite(pairing ? "ERR pairing denied\n" : "ERR denied\n"); return; }
    if (pairing) { consoleWrite("OK paired\n"); return; }
    char hex[65];
    hexEncode(mac, 32, hex);
    consolef("UNLOCK %s\n", hex);
}

static void cmdUnlock(int argc, char** argv) {
    const char* sub = argc > 1 ? argv[1] : "list";
    if (!strcmp(sub, "list")) {
        char name[24];
        int n = 0;
        for (int i = 0; i < UNLOCK_MAX_PCS; i++) {
            if (unlock::name(i, name, sizeof(name))) { consolef("  %d: %s\n", i, name); n++; }
        }
        if (!n) consoleWrite("  (none)\n");
    } else if (!strcmp(sub, "remove") && argc >= 3) {
        consoleWrite(unlock::remove(atoi(argv[2])) ? "OK\n" : "ERR no such PC\n");
    } else if (!strcmp(sub, "pair") && argc >= 5) {
        // unlock pair <pc-id hex16> <key hex64> <name>  (confirmed on the device)
        uint8_t id[UNLOCK_PC_ID_LEN], key[UNLOCK_KEY_LEN];
        if (hexDecode(argv[2], strlen(argv[2]), id, sizeof(id)) != UNLOCK_PC_ID_LEN ||
            hexDecode(argv[3], strlen(argv[3]), key, sizeof(key)) != UNLOCK_KEY_LEN) {
            consoleWrite("ERR bad pairing data\n");
            return;
        }
        static int pairingCtx = 1;
        if (!unlock::pair(id, key, argv[4], "USB", serialUnlockReply, &pairingCtx)) consoleWrite("ERR busy\n");
        crypto::wipe(key, sizeof(key));
    } else if (argc >= 3) {
        // unlock <pc-id hex16> <challenge hex64>
        uint8_t id[UNLOCK_PC_ID_LEN], chal[UNLOCK_CHAL_LEN];
        if (hexDecode(argv[1], strlen(argv[1]), id, sizeof(id)) != UNLOCK_PC_ID_LEN ||
            hexDecode(argv[2], strlen(argv[2]), chal, sizeof(chal)) != UNLOCK_CHAL_LEN) {
            consoleWrite("ERR bad request\n");
            return;
        }
        unlock::respond(id, chal, sizeof(chal), "USB", serialUnlockReply, nullptr);
    } else {
        consoleWrite("ERR usage: unlock list|remove <n>\n");
    }
}

static void cmdPasskeys(int argc, char** argv) {
    if (argc >= 3 && !strcmp(argv[1], "del")) {
        consoleWrite(creds::residentDelete(atoi(argv[2])) ? "OK\n" : "ERR no such slot\n");
        return;
    }
    ResidentCredential c;
    int n = 0;
    for (int i = 0; i < creds::residentCapacity(); i++) {
        if (!creds::residentGet(i, &c)) continue;
        consolef("  %d: %s  %s\n", i, c.rpId, c.userName);
        n++;
    }
    if (!n) consoleWrite("  (none)\n");
}

// Bluetooth keyboard: status, on/off (applies after a reboot), type a TOTP code.
static void cmdKeyboard(int argc, char** argv) {
    if (argc >= 2 && (!strcmp(argv[1], "on") || !strcmp(argv[1], "off"))) {
        settings::setKeyboard(!strcmp(argv[1], "on"));
        consolef("OK keyboard %s after `reboot`\n", settings::keyboard() ? "on" : "off");
    } else if (argc >= 3 && !strcmp(argv[1], "type")) {
        TotpAccount a;
        time_t now = network::now();
        if (!now) { consoleWrite("ERR clock not set\n"); return; }
        if (!totp::get(atoi(argv[2]), &a)) { consoleWrite("ERR no such account\n"); return; }
        char code[12];
        snprintf(code, sizeof(code), "%0*lu", a.digits, (unsigned long)totp::generate(a, now));
        crypto::wipe(&a, sizeof(a));
        int hosts = ble::typeText(code);
        crypto::wipe(code, sizeof(code));
        consolef(hosts ? "OK typed into %d host(s)\n" : "ERR no keyboard host connected\n", hosts);
    } else {
        consolef("  keyboard %s, %d host(s) connected%s\n", ble::keyboardEnabled() ? "on" : "off",
                 ble::keyboardHosts(),
                 settings::keyboard() != ble::keyboardEnabled() ? " (changes after reboot)" : "");
    }
}

// backup <key> | restore begin <key> <nonce> <len> | restore data <hex> | restore end
// (driven by tools/authkey.py backup / restore, which derives the key from a passphrase)
static void cmdBackup(int argc, char** argv) {
    uint8_t key[32], nonce[12];
    bool isRestore = !strcmp(argv[0], "restore");
    if (!isRestore) {
        if (argc >= 2 && hexDecode(argv[1], strlen(argv[1]), key, sizeof(key)) == 32) backup::exportStart(key);
        else consoleWrite("ERR use tools/authkey.py backup <file>\n");
    } else if (argc >= 5 && !strcmp(argv[1], "begin") &&
               hexDecode(argv[2], strlen(argv[2]), key, sizeof(key)) == 32 &&
               hexDecode(argv[3], strlen(argv[3]), nonce, sizeof(nonce)) == 12) {
        backup::restoreBegin(key, nonce, (size_t)atol(argv[4]));
    } else if (argc >= 3 && !strcmp(argv[1], "data")) {
        backup::restoreData(argv[2]);
    } else if (argc >= 2 && !strcmp(argv[1], "end")) {
        backup::restoreEnd();
    } else {
        consoleWrite("ERR use tools/authkey.py restore <file>\n");
    }
    crypto::wipe(key, sizeof(key));
}

// CTAP over the console, for the PC test harness: "ctap <hex>" -> "CTAP <hex>"
static void serialCtapReply(const uint8_t* data, size_t len) {
    // One write, so other log output can't land inside the line; the buffer
    // only exists while replying (RAM is needed for TLS the rest of the time).
    char* line = (char*)malloc(2 * len + 8);
    if (!line) { consoleWrite("CTAP 7f\n"); return; }   // CTAP1_ERR_OTHER
    memcpy(line, "CTAP ", 5);
    hexEncode(data, len, line + 5);
    strcat(line, "\n");
    consoleWrite(line);
    free(line);
}

static void cmdCtap(int argc, char** argv) {
    static uint8_t msg[FIDO_MAX_MSG];
    if (argc < 2) { consoleWrite("ERR usage: ctap <hex> | ctap cancel\n"); return; }
    if (!strcmp(argv[1], "cancel")) {
        // The pending request (if any) is answered with KEEPALIVE_CANCEL.
        ctap::cancel(CtapTransport::Serial);
        return;
    }
    int n = hexDecode(argv[1], strlen(argv[1]), msg, sizeof(msg));
    if (n <= 0) { consoleWrite("ERR bad hex\n"); return; }
    if (!ctap::submit(CtapTransport::Serial, msg, n, serialCtapReply)) {
        uint8_t busy = CTAP1_ERR_CHANNEL_BUSY;
        serialCtapReply(&busy, 1);
    }
}

static void execute(char* line) {
    char* argv[MAX_ARGS];
    int argc = tokenize(line, argv);
    if (argc == 0) return;
    const char* cmd = argv[0];

    if (!strcmp(cmd, "help") || !strcmp(cmd, "?")) help();
    else if (!strcmp(cmd, "status")) status();
    else if (!strcmp(cmd, "totp")) cmdTotp(argc, argv);
    else if (!strcmp(cmd, "wifi")) cmdWifi(argc, argv);
    else if (!strcmp(cmd, "portal")) cmdPortal(argc, argv);
    else if (!strcmp(cmd, "wol")) cmdWol(argc, argv);
    else if (!strcmp(cmd, "tg")) cmdTelegram(argc, argv);
    else if (!strcmp(cmd, "pve")) cmdPve(argc, argv);
    else if (!strcmp(cmd, "tlstest")) {
        // Verified TLS connection to the hybrid tunnel server: shows whether
        // its certificate chain still verifies and how much RAM TLS needs.
        uint32_t before = ESP.getFreeHeap();
        WiFiClientSecure c;
        c.setCACert(TUNNEL_ROOT_CAS);
        c.setHandshakeTimeout(12);
        uint32_t t0 = millis();
        bool ok = c.connect("cable.ua5v.com", 443);
        uint32_t during = ESP.getFreeHeap();
        char why[100] = "";
        int code = ok ? 0 : c.lastError(why, sizeof(why));
        c.stop();
        consolef("%s tunnel TLS %lu ms, heap before %u, after handshake %u, min ever %u, err %d %s\n", ok ? "OK" : "ERR",
                 (unsigned long)(millis() - t0), (unsigned)before, (unsigned)during, (unsigned)ESP.getMinFreeHeap(), code, why);
        if (!ok) {
            // Fetch the chain without verification (nothing is sent), then let
            // mbedTLS verify it with our roots to get the real reason.
            WiFiClientSecure d;
            d.setInsecure();
            d.setHandshakeTimeout(12);
            if (!d.connect("cable.ua5v.com", 443)) { consoleWrite("  (diagnostic connect failed)\n"); return; }
            const mbedtls_x509_crt* crt = d.getPeerCertificate();
            mbedtls_x509_crt ca;
            mbedtls_x509_crt_init(&ca);
            int rc = mbedtls_x509_crt_parse(&ca, (const unsigned char*)TUNNEL_ROOT_CAS, strlen(TUNNEL_ROOT_CAS) + 1);
            uint32_t flags = 0;
            int vr = crt ? mbedtls_x509_crt_verify((mbedtls_x509_crt*)crt, &ca, nullptr, "cable.ua5v.com", &flags,
                                                   nullptr, nullptr) : -1;
            char info[240] = "";
            mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
            for (char* q = info; *q; q++) if (*q == '\n') *q = ';';
            for (const mbedtls_x509_crt* x = crt; x; x = x->next) {
                char sub[90] = "?";
                mbedtls_x509_dn_gets(sub, sizeof(sub), &x->subject);
                consolef("  chain: %s\n", sub);
            }
            consolef("  roots parsed: rc=%d; verify=%d flags=0x%08lx %s; min heap %u\n", rc, vr, (unsigned long)flags,
                     info, (unsigned)ESP.getMinFreeHeap());
            mbedtls_x509_crt_free(&ca);
            d.stop();
        }
    }
    else if (!strcmp(cmd, "mem")) {
        consolef("heap %u free, largest %u, min ever %u; loop stack: %u bytes never used\n",
                 (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap(), (unsigned)ESP.getMinFreeHeap(),
                 (unsigned)uxTaskGetStackHighWaterMark(nullptr));
    }
    else if (!strcmp(cmd, "passkeys") || !strcmp(cmd, "passkey")) cmdPasskeys(argc, argv);
    else if (!strcmp(cmd, "unlock")) cmdUnlock(argc, argv);
    else if (!strcmp(cmd, "ctap")) cmdCtap(argc, argv);
    else if (!strcmp(cmd, "backup") || !strcmp(cmd, "restore")) cmdBackup(argc, argv);
#ifdef AUTHKEY_TEST_HOOKS
    // Test builds only: lets the PC harness stand in for the buttons. Never
    // enable in firmware you use, or software on the PC could approve logins.
    else if (!strcmp(cmd, "approve")) ctap::userApprove();
    else if (!strcmp(cmd, "approve!")) approval::forceApprove();
    else if (!strcmp(cmd, "deny")) ctap::userDeny();
    else if (!strcmp(cmd, "uvpin") && argc >= 2) consoleWrite(ctap::userSubmitPin(argv[1]) ? "OK\n" : "ERR\n");
    else if (!strcmp(cmd, "setpin") && argc >= 2) consoleWrite(settings::pinSet(argv[1]) ? "OK\n" : "ERR\n");
    else if (!strcmp(cmd, "clearpin")) { settings::pinClear(); consoleWrite("OK\n"); }
#endif
    else if (!strcmp(cmd, "time")) {
        if (argc >= 3 && !strcmp(argv[1], "set")) {
            network::setTimeUtc((time_t)strtoll(argv[2], nullptr, 10));
            consoleWrite("OK\n");
        } else {
            consolef("UTC %ld%s\n", (long)network::now(), network::timeValid() ? "" : " (not set)");
        }
    } else if (!strcmp(cmd, "tz") && argc >= 2) {
        settings::setTimezone(argv[1]);
        network::applyTimezone();
        consoleWrite("OK\n");
    } else if (!strcmp(cmd, "auto") && argc >= 2) {
        settings::setAutoApprove(!strcmp(argv[1], "on"));
        consolef("OK auto-approve %s\n", settings::autoApprove() ? "ON" : "off");
    } else if (!strcmp(cmd, "lock")) {
        settings::uvSessionEnd();
        consoleWrite("OK locked: the next verified request asks for the PIN\n");
    } else if (!strcmp(cmd, "uvhours") && argc >= 2) {
        settings::setUvSessionHours(atoi(argv[1]));
        consolef("OK unlocked session lasts %d hour(s) (0 = until reboot)\n", settings::uvSessionHours());
    } else if (!strcmp(cmd, "pin")) {
        consolef("PIN %s, %d tries left. Set or change it on the device (menu > Device PIN).\n",
                 settings::pinIsSet() ? "set" : "not set", settings::pinRetries());
    } else if (!strcmp(cmd, "hybrid") && argc >= 2) {
        if (!strcmp(argv[1], "stop")) { hybrid::stop("console"); consoleWrite("OK\n"); }
        else consoleWrite(hybrid::start(argv[1]) ? "OK starting\n" : "ERR invalid FIDO QR\n");
    } else if (!strcmp(cmd, "bt") && argc >= 2 && !strcmp(argv[1], "forget")) {
        ble::forgetBonds();
        consoleWrite("OK\n");
    } else if (!strcmp(cmd, "log") && argc >= 2 && !strcmp(argv[1], "clear")) {
        logClear();
        consoleWrite("OK\n");
    } else if (!strcmp(cmd, "kbd")) {
        cmdKeyboard(argc, argv);
    } else if (!strcmp(cmd, "log")) {
        for (int i = 0; i < logCount(); i++) consolef("  %s\n", logLine(i));
    } else if (!strcmp(cmd, "reboot")) {
        consoleWrite("Rebooting...\n");
        logFlush();
        delay(100);
        ESP.restart();
    } else {
        consolef("ERR unknown command '%s' (try help)\n", cmd);
    }
}

void init() {
    s_len = 0;
}

void run(const char* line, String* output) {
    size_t n = strlen(line) + 1;
    char* buf = (char*)malloc(n);   // execute() edits the line; only held during the command
    if (!buf) { if (output) *output += "ERR out of memory"; return; }
    memcpy(buf, line, n);
    consoleCapture(output);
    execute(buf);
    consoleCapture(nullptr);
    crypto::wipe(buf, n);
    free(buf);
}

bool sensitive(const char* line) {
    while (*line == ' ') line++;
    // Weakens protection, injects input, reaches secrets or erases evidence.
    static const char* const RISKY[] = {
        "auto on", "passkey del", "passkeys del", "unlock ", "bt forget", "ctap", "backup", "restore",
        "wifi del", "wifi reset", "kbd type", "uvhours", "log clear", "hybrid", "time set", "tz ",
        "approve", "uvpin", "setpin", "clearpin", "pve unpin",
    };
    if (!strcmp(line, "unlock") || !strncmp(line, "unlock list", 11)) return false;
    for (const char* r : RISKY) if (!strncmp(line, r, strlen(r))) return true;
    return false;
}

void loop() {
    while (Serial.available()) {
        int c = Serial.read();
        if (c < 0) break;
        if (c == '\r' || c == '\n') {
            if (s_len) {
                s_line[s_len] = '\0';
                execute(s_line);
                crypto::wipe(s_line, s_len);   // may have held a secret
                s_len = 0;
            }
        } else if (c == 8 || c == 127) {
            if (s_len) s_len--;
        } else if (s_len < sizeof(s_line) - 1) {
            s_line[s_len++] = (char)c;
        }
    }
}

}  // namespace cli
