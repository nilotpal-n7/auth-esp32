#include "cli/cli.h"
#include "config.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "fido/credentials.h"
#include "fido/ctap2.h"
#include "net/network.h"
#include "totp/totp.h"
#include "transport/ble.h"
#include "transport/hybrid.h"
#include "util/codec.h"

#include <WiFi.h>

namespace cli {

static char   s_line[2 * FIDO_MAX_MSG + 64];
static size_t s_len = 0;

#define MAX_ARGS 6

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
        "  wifi connect | wifi reset   reconnect | restore secrets.h list\n"
        "  time | time set <unix>      show / set UTC clock\n"
        "  tz <POSIX TZ>               clock timezone, e.g. IST-5:30, CET-1CEST,M3.5.0,M10.5.0/3\n"
        "  passkeys | passkey del <n>  list / delete discoverable credentials\n"
        "  pin                         device PIN status (set it on the device)\n"
        "  auto on|off                 hands-free sign-in + registration (no OK/PIN)\n"
        "  hybrid <FIDO:/...> | hybrid stop   phone-style login from a QR string\n"
        "  bt forget                   remove all Bluetooth bonds\n"
        "  log                         recent events\n"
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
    consolef("  Bluetooth: %s, %d bond(s), MAC %s\n",
             ble::connected() ? "connected" : "advertising", ble::bondCount(),
             WiFi.macAddress().c_str());
    consolef("  TOTP:      %d account(s)\n", totp::count());
    consolef("  Passkeys:  %d/%d discoverable, sign count %lu\n", creds::residentCount(),
             creds::residentCapacity(), (unsigned long)settings::signCount());
    consolef("  PIN:       %s, auto-approve %s\n",
             settings::pinIsSet() ? "set" : "not set", settings::autoApprove() ? "ON" : "off");
    consolef("  Hybrid:    %s\n", hybrid::stateText());
    consolef("  OTA:       %s\n", network::otaEnabled() ? "enabled" : "disabled (no password)");
    consolef("  Heap:      %u free\n", (unsigned)ESP.getFreeHeap());
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

// CTAP over the console, for the PC test harness: "ctap <hex>" -> "CTAP <hex>"
static void serialCtapReply(const uint8_t* data, size_t len) {
    static char hex[2 * FIDO_MAX_MSG + 8];
    hexEncode(data, len, hex);
    consoleWrite("CTAP ");
    consoleWrite(hex);
    consoleWrite("\n");
}

static void cmdCtap(int argc, char** argv) {
    static uint8_t msg[FIDO_MAX_MSG];
    if (argc < 2) { consoleWrite("ERR usage: ctap <hex>\n"); return; }
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
    else if (!strcmp(cmd, "passkeys") || !strcmp(cmd, "passkey")) cmdPasskeys(argc, argv);
    else if (!strcmp(cmd, "ctap")) cmdCtap(argc, argv);
#ifdef AUTHKEY_TEST_HOOKS
    // Test builds only: lets the PC harness stand in for the buttons. Never
    // enable in firmware you use, or software on the PC could approve logins.
    else if (!strcmp(cmd, "approve")) ctap::userApprove();
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
    } else if (!strcmp(cmd, "pin")) {
        consolef("PIN %s, %d tries left. Set or change it on the device (menu > Device PIN).\n",
                 settings::pinIsSet() ? "set" : "not set", settings::pinRetries());
    } else if (!strcmp(cmd, "hybrid") && argc >= 2) {
        if (!strcmp(argv[1], "stop")) { hybrid::stop("console"); consoleWrite("OK\n"); }
        else consoleWrite(hybrid::start(argv[1]) ? "OK starting\n" : "ERR invalid FIDO QR\n");
    } else if (!strcmp(cmd, "bt") && argc >= 2 && !strcmp(argv[1], "forget")) {
        ble::forgetBonds();
        consoleWrite("OK\n");
    } else if (!strcmp(cmd, "log")) {
        for (int i = 0; i < logCount(); i++) consolef("  %s\n", logLine(i));
    } else if (!strcmp(cmd, "reboot")) {
        consoleWrite("Rebooting...\n");
        delay(100);
        ESP.restart();
    } else {
        consolef("ERR unknown command '%s' (try help)\n", cmd);
    }
}

void init() {
    s_len = 0;
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
