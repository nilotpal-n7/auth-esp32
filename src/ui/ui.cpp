#include "ui/ui.h"
#include "ui/buttons.h"
#include "config.h"
#include "core/approval.h"
#include "core/log.h"
#include "core/settings.h"
#include "fido/credentials.h"
#include "fido/ctap2.h"
#include "net/network.h"
#include "net/portal.h"
#include "totp/totp.h"
#include "transport/ble.h"
#include "transport/hybrid.h"
#include "unlock/unlock.h"

#include <U8g2lib.h>
#include <WiFi.h>
#include <Wire.h>

namespace ui {

#if OLED_DRIVER == OLED_DRIVER_SH1106
static U8G2_SH1106_128X64_NONAME_F_HW_I2C g_lcd(U8G2_R0, U8X8_PIN_NONE);
#else
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C g_lcd(U8G2_R0, U8X8_PIN_NONE);
#endif

static const int W = 128;

enum class Screen : uint8_t {
    Home, Menu, Passkeys, PasskeyDetail, PinMenu, PinEntry, Wifi, Portal, Bluetooth, Log, Info,
    ConfirmReset,
};

enum class PinPurpose : uint8_t { CtapUv, Approval, SetNew, SetConfirm, ChangeOld, RemoveOld };

static Screen   s_screen = Screen::Home;
static int      s_totpIndex = 0;
static int      s_menuIndex = 0;
static int      s_listIndex = 0;
static int      s_portalSel = 0;
static int      s_listSlots[FIDO_MAX_RESIDENT];
static int      s_listCount = 0;
static uint32_t s_lastInput = 0;
static uint32_t s_lastDraw = 0;
static bool     s_asleep = false;
static bool     s_dirty = true;
static char     s_toast[32] = "";
static uint32_t s_toastUntil = 0;

// PIN entry state
static PinPurpose s_pinPurpose;
static char       s_pin[FIDO_PIN_MAX_LEN + 1];
static int        s_pinLen = 0;
static int        s_pinDigit = 0;
static char       s_pinFirst[FIDO_PIN_MAX_LEN + 1];
static Screen     s_pinReturn = Screen::Menu;

static const char* MENU_ITEMS[] = {
    "Passkeys", "Auto-approve", "Device PIN", "WiFi", "Campus net", "Bluetooth", "Event log",
    "Device info", "Reset passkeys", "Back",
};
static const int MENU_COUNT = sizeof(MENU_ITEMS) / sizeof(MENU_ITEMS[0]);

static void toast(const char* msg) {
    strlcpy(s_toast, msg, sizeof(s_toast));
    s_toastUntil = millis() + 2000;
    s_dirty = true;
}

// --- Drawing helpers ---------------------------------------------------------

static void centered(int y, const char* s) {
    int w = g_lcd.getStrWidth(s);
    g_lcd.drawStr((W - w) / 2 > 0 ? (W - w) / 2 : 0, y, s);
}

static void statusBar() {
    g_lcd.setFont(u8g2_font_5x7_tr);
    char clock[8];
    network::localClock(clock, sizeof(clock));
    g_lcd.drawStr(0, 7, clock[0] ? clock : "--:--");
    int x = W;
    auto right = [&](const char* s) {
        x -= g_lcd.getStrWidth(s) + 3;
        g_lcd.drawStr(x, 7, s);
    };
    right(ble::connected() ? (ble::secured() ? "BT*" : "BT") : "bt");
    bool campus = portal::haveCredentials() && network::connected();
    if (!campus) right(network::connected() ? "WiFi" : "----");
    else if (!portal::online()) right(portal::paused() ? "IITG-" : "!NET");   // login needed
    if (settings::autoApprove()) right("AUTO");
    if (hybrid::state() != hybrid::State::Idle) right("HY");

    // Campus session next to the clock: "IITG <check> 14m" = online, refreshed in 14 min.
    if (campus && portal::online()) {
        int cx = 31;
        if (cx + 20 < x - 3) {
            g_lcd.drawStr(cx, 7, "IITG");
            cx += 22;
            if (cx + 6 < x - 3) {   // check mark
                g_lcd.drawLine(cx, 4, cx + 2, 6);
                g_lcd.drawLine(cx + 2, 6, cx + 6, 1);
                cx += 9;
            }
            if (portal::ownsSession()) {
                char m[8];
                snprintf(m, sizeof(m), "%lum", (unsigned long)(portal::secondsToNext() / 60));
                if (cx + g_lcd.getStrWidth(m) < x - 3) g_lcd.drawStr(cx, 7, m);
            }
        }
    }
    g_lcd.drawHLine(0, 9, W);
}

static void footer(const char* text) {
    g_lcd.setFont(u8g2_font_4x6_tr);
    g_lcd.drawHLine(0, 56, W);
    centered(63, text);
}

static void list(const char* title, const char* const* items, int count, int sel,
                 const char* (*itemFn)(int) = nullptr) {
    g_lcd.setFont(u8g2_font_6x10_tr);
    g_lcd.drawStr(0, 8, title);
    g_lcd.drawHLine(0, 10, W);
    const int rows = 4;
    int first = sel - rows + 1 > 0 ? sel - rows + 1 : 0;
    for (int r = 0; r < rows && first + r < count; r++) {
        int i = first + r;
        int y = 22 + r * 11;
        const char* text = itemFn ? itemFn(i) : items[i];
        if (i == sel) {
            g_lcd.drawBox(0, y - 9, W, 11);
            g_lcd.setDrawColor(0);
            g_lcd.drawStr(3, y, text);
            g_lcd.setDrawColor(1);
        } else {
            g_lcd.drawStr(3, y, text);
        }
    }
}

// --- Screens -----------------------------------------------------------------

static void drawHome() {
    statusBar();
    int n = totp::count();
    if (n == 0) {
        g_lcd.setFont(u8g2_font_6x10_tr);
        centered(28, "No TOTP accounts");
        g_lcd.setFont(u8g2_font_4x6_tr);
        centered(40, "Add over USB serial:");
        centered(48, "totp add <name> <secret>");
        footer("hold OK: menu");
        return;
    }
    if (s_totpIndex >= n) s_totpIndex = 0;
    TotpAccount a;
    if (!totp::get(s_totpIndex, &a)) return;

    g_lcd.setFont(u8g2_font_6x10_tr);
    centered(21, a.name);

    time_t now = network::now();
    char code[12] = "--- ---";
    uint8_t left = 0;
    if (now) {
        totp::format(a, totp::generate(a, now), code, sizeof(code));
        left = totp::secondsRemaining(a, now);
    }
    g_lcd.setFont(a.digits == 8 ? u8g2_font_logisoso16_tn : u8g2_font_logisoso22_tn);
    centered(47, code);

    if (now) {
        int period = a.period ? a.period : 30;
        g_lcd.drawFrame(0, 51, W, 4);
        g_lcd.drawBox(0, 51, (W * left) / period, 4);
    } else {
        g_lcd.setFont(u8g2_font_4x6_tr);
        centered(55, "waiting for time sync");
    }
    if (n > 1) {
        char pos[24];
        snprintf(pos, sizeof(pos), "%d/%d", s_totpIndex + 1, n);
        g_lcd.setFont(u8g2_font_4x6_tr);
        g_lcd.drawStr(W - g_lcd.getStrWidth(pos), 63, pos);
    }
    memset(&a, 0, sizeof(a));
}

static const char* menuItemText(int i) {
    static char buf[24];
    if (i == 1) {
        snprintf(buf, sizeof(buf), "Auto-approve: %s", settings::autoApprove() ? "ON" : "off");
        return buf;
    }
    if (i == 2) {
        snprintf(buf, sizeof(buf), "Device PIN: %s", settings::pinIsSet() ? "set" : "none");
        return buf;
    }
    if (i == 4 && portal::haveCredentials()) {
        snprintf(buf, sizeof(buf), "Campus: %s", portal::stateStr());
        return buf;
    }
    return MENU_ITEMS[i];
}

static const char* passkeyItemText(int i) {
    static char buf[24];
    if (s_listCount == 0) return "(none)";
    ResidentCredential c;
    if (!creds::residentGet(s_listSlots[i], &c)) return "?";
    strlcpy(buf, c.rpId, sizeof(buf));
    return buf;
}

static void reloadPasskeys() {
    s_listCount = 0;
    for (int i = 0; i < creds::residentCapacity(); i++) {
        ResidentCredential c;
        if (creds::residentGet(i, &c)) s_listSlots[s_listCount++] = i;
    }
    if (s_listIndex >= s_listCount) s_listIndex = s_listCount ? s_listCount - 1 : 0;
}

static void drawPasskeyDetail() {
    ResidentCredential c;
    g_lcd.setFont(u8g2_font_6x10_tr);
    if (!creds::residentGet(s_listSlots[s_listIndex], &c)) {
        centered(30, "Not found");
        return;
    }
    g_lcd.drawStr(0, 10, c.rpId);
    g_lcd.drawHLine(0, 12, W);
    g_lcd.setFont(u8g2_font_5x7_tr);
    g_lcd.drawStr(0, 24, c.userName[0] ? c.userName : "(no user name)");
    g_lcd.drawStr(0, 34, c.displayName);
    footer("hold OK: delete  DOWN: back");
}

static void drawPinEntry() {
    g_lcd.setFont(u8g2_font_6x10_tr);
    const char* title = "Enter PIN";
    switch (s_pinPurpose) {
        case PinPurpose::CtapUv:
        case PinPurpose::Approval:   title = "PIN to approve"; break;
        case PinPurpose::SetNew:     title = "New PIN"; break;
        case PinPurpose::SetConfirm: title = "Confirm new PIN"; break;
        case PinPurpose::ChangeOld:  title = "Current PIN"; break;
        case PinPurpose::RemoveOld:  title = "PIN to remove"; break;
    }
    centered(10, title);
    if (s_pinPurpose == PinPurpose::CtapUv) {
        const CtapPrompt* p = ctap::prompt();
        if (p) { g_lcd.setFont(u8g2_font_5x7_tr); centered(20, p->rpId); }
    } else if (s_pinPurpose == PinPurpose::Approval) {
        const approval::Request* a = approval::pending();
        if (a) { g_lcd.setFont(u8g2_font_5x7_tr); centered(20, a->title); }
    }
    // Entered digits as '*', current digit shown in a box.
    g_lcd.setFont(u8g2_font_9x15_tr);
    int slots = s_pinLen + 1 <= FIDO_PIN_MAX_LEN ? s_pinLen + 1 : FIDO_PIN_MAX_LEN;
    int x0 = (W - slots * 12) / 2;
    for (int i = 0; i < slots; i++) {
        int x = x0 + i * 12;
        if (i < s_pinLen) g_lcd.drawStr(x + 2, 40, "*");
        else {
            char d[2] = {(char)('0' + s_pinDigit), 0};
            g_lcd.drawFrame(x, 27, 12, 16);
            g_lcd.drawStr(x + 2, 40, d);
        }
    }
    char tries[24] = "";
    if (s_pinPurpose == PinPurpose::CtapUv || s_pinPurpose == PinPurpose::Approval ||
        s_pinPurpose == PinPurpose::ChangeOld ||
        s_pinPurpose == PinPurpose::RemoveOld) {
        snprintf(tries, sizeof(tries), "%d tries left", settings::pinRetries());
        g_lcd.setFont(u8g2_font_4x6_tr);
        centered(51, tries);
    }
    footer("U/D digit OK next  hold OK done");
}

static void drawWifi() {
    g_lcd.setFont(u8g2_font_6x10_tr);
    g_lcd.drawStr(0, 8, "WiFi");
    g_lcd.drawHLine(0, 10, W);
    g_lcd.setFont(u8g2_font_5x7_tr);
    char line[40];
    if (network::connected()) {
        snprintf(line, sizeof(line), "SSID %s", network::ssid());
        g_lcd.drawStr(0, 20, line);
        snprintf(line, sizeof(line), "IP   %s", network::ip().c_str());
        g_lcd.drawStr(0, 29, line);
        snprintf(line, sizeof(line), "RSSI %d dBm", WiFi.RSSI());
        g_lcd.drawStr(0, 38, line);
    } else {
        g_lcd.drawStr(0, 20, "Not connected");
    }
    snprintf(line, sizeof(line), "%d saved network(s)", network::savedCount());
    g_lcd.drawStr(0, 47, line);
    footer("OK: reconnect  DOWN: back");
}

static const char* portalAction(int i) {
    switch (i) {
        case 0: return "Login now";
        case 1: return "Logout";
        case 2: return portal::enabled() ? "Auto-login: ON" : "Auto-login: off";
        default: return "Back";
    }
}

static void drawPortal() {
    g_lcd.setFont(u8g2_font_6x10_tr);
    g_lcd.drawStr(0, 8, "Campus net");
    g_lcd.setFont(u8g2_font_5x7_tr);
    const char* mode = portal::enabled() ? (portal::paused() ? "PAUSED" : "AUTO") : "MANUAL";
    g_lcd.drawStr(W - g_lcd.getStrWidth(mode), 8, mode);
    g_lcd.drawHLine(0, 10, W);

    char line[40];
    if (!portal::haveCredentials()) {
        g_lcd.drawStr(0, 21, "No IITG credentials.");
        g_lcd.drawStr(0, 30, "Set IITG_USERNAME and");
        g_lcd.drawStr(0, 39, "IITG_PASSWORD in .env");
    } else {
        snprintf(line, sizeof(line), "State: %s", portal::stateStr());
        g_lcd.drawStr(0, 19, line);
        snprintf(line, sizeof(line), "User:  %s", portal::user());
        g_lcd.drawStr(0, 27, line);
        g_lcd.drawStr(0, 35, portal::lastResult()[0] ? portal::lastResult() : "-");
        uint32_t s = portal::secondsToNext();
        if (portal::online() && portal::ownsSession())
            snprintf(line, sizeof(line), "Refresh %lu:%02lu  in:%d", (unsigned long)(s / 60),
                     (unsigned long)(s % 60), portal::logins());
        else
            snprintf(line, sizeof(line), "Next check %lus  in:%d", (unsigned long)s, portal::logins());
        g_lcd.drawStr(0, 43, line);
    }
    // Action selector
    g_lcd.drawBox(0, 46, W, 10);
    g_lcd.setDrawColor(0);
    snprintf(line, sizeof(line), "< %s >", portalAction(s_portalSel));
    centered(54, line);
    g_lcd.setDrawColor(1);
    footer("U/D choose  OK do  hold OK back");
}

static void drawBluetooth() {
    g_lcd.setFont(u8g2_font_6x10_tr);
    g_lcd.drawStr(0, 8, "Bluetooth");
    g_lcd.drawHLine(0, 10, W);
    g_lcd.setFont(u8g2_font_5x7_tr);
    char line[40];
    snprintf(line, sizeof(line), "Name %s", FW_NAME);
    g_lcd.drawStr(0, 20, line);
    if (ble::connected()) snprintf(line, sizeof(line), "%d link(s)%s", ble::linkCount(), ble::secured() ? ", secure" : "");
    else strlcpy(line, "Advertising", sizeof(line));
    g_lcd.drawStr(0, 29, line);
    snprintf(line, sizeof(line), "%d paired device(s)", ble::bondCount());
    g_lcd.drawStr(0, 38, line);
    if (settings::keyboard() != ble::keyboardEnabled())
        snprintf(line, sizeof(line), "Keyboard %s after reboot", settings::keyboard() ? "ON" : "off");
    else if (ble::keyboardEnabled())
        snprintf(line, sizeof(line), "Keyboard ON, %d host(s)", ble::keyboardHosts());
    else
        strlcpy(line, "Keyboard off", sizeof(line));
    g_lcd.drawStr(0, 47, line);
    footer("OK: keyboard on/off  hold OK: forget");
}

static void drawLog() {
    g_lcd.setFont(u8g2_font_4x6_tr);
    int n = logCount();
    const int rows = 9;
    int first = n - rows - s_listIndex;
    if (first < 0) first = 0;
    for (int r = 0; r < rows && first + r < n; r++) g_lcd.drawStr(0, 6 + r * 7, logLine(first + r));
}

static void drawInfo() {
    g_lcd.setFont(u8g2_font_5x7_tr);
    char line[40];
    snprintf(line, sizeof(line), "%s v%s", FW_NAME, FW_VERSION);
    g_lcd.drawStr(0, 7, line);
    g_lcd.drawHLine(0, 9, W);
    snprintf(line, sizeof(line), "TOTP accounts: %d", totp::count());
    g_lcd.drawStr(0, 18, line);
    snprintf(line, sizeof(line), "Passkeys: %d/%d", creds::residentCount(), creds::residentCapacity());
    g_lcd.drawStr(0, 27, line);
    snprintf(line, sizeof(line), "Sign count: %lu", (unsigned long)settings::signCount());
    g_lcd.drawStr(0, 36, line);
    if (network::connected()) snprintf(line, sizeof(line), "Web: http://%s/", network::ip().c_str());
    else snprintf(line, sizeof(line), "Free heap: %u", (unsigned)ESP.getFreeHeap());
    g_lcd.drawStr(0, 45, line);
    snprintf(line, sizeof(line), "Up %lus", (unsigned long)(millis() / 1000));
    g_lcd.drawStr(0, 54, line);
}

static void drawConfirmReset() {
    g_lcd.setFont(u8g2_font_6x10_tr);
    centered(14, "Delete ALL passkeys?");
    g_lcd.setFont(u8g2_font_5x7_tr);
    centered(28, "Every registered site");
    centered(37, "will stop working.");
    footer("hold OK: reset  DOWN: cancel");
}

static void drawPrompt(const CtapPrompt* p) {
    g_lcd.setFont(u8g2_font_6x10_tr);
    const char* title = "";
    switch (p->kind) {
        case PromptKind::Register: title = p->excluded ? "ALREADY REGISTERED" : "REGISTER PASSKEY"; break;
        case PromptKind::Login:    title = "SIGN IN"; break;
        case PromptKind::Reset:    title = "RESET ALL PASSKEYS"; break;
        case PromptKind::Select:   title = "USE THIS KEY?"; break;
        default: break;
    }
    g_lcd.drawBox(0, 0, W, 11);
    g_lcd.setDrawColor(0);
    centered(9, title);
    g_lcd.setDrawColor(1);

    if (p->rpId[0]) {
        g_lcd.setFont(strlen(p->rpId) > 18 ? u8g2_font_5x7_tr : u8g2_font_7x13B_tr);
        centered(27, p->rpId);
    }
    g_lcd.setFont(u8g2_font_5x7_tr);
    if (p->userName[0]) centered(38, p->userName);
    else if (p->kind == PromptKind::Login && p->accountCount > 1) {
        char buf[24];
        snprintf(buf, sizeof(buf), "%d accounts", p->accountCount);
        centered(38, buf);
    }
    uint32_t elapsed = millis() - p->startedMs;
    uint32_t left = elapsed < FIDO_USER_TIMEOUT_MS ? (FIDO_USER_TIMEOUT_MS - elapsed) / 1000 : 0;
    char t[16];
    snprintf(t, sizeof(t), "%lus", (unsigned long)left);
    g_lcd.drawStr(W - g_lcd.getStrWidth(t), 47, t);
    g_lcd.drawStr(0, 47, p->transport == CtapTransport::Ble ? "via BT" :
                         p->transport == CtapTransport::Hybrid ? "via hybrid" : "via USB");
    footer(p->kind == PromptKind::Reset ? "hold OK: reset   DOWN: deny"
                                        : p->needPin ? "OK: enter PIN   DOWN: deny"
                                                     : "OK: approve   DOWN: deny");
}

static void drawPairing(uint32_t code) {
    g_lcd.setFont(u8g2_font_6x10_tr);
    centered(10, "Bluetooth pairing");
    g_lcd.setFont(u8g2_font_5x7_tr);
    centered(22, "Does the PC show:");
    char buf[8];
    snprintf(buf, sizeof(buf), "%06lu", (unsigned long)code);
    g_lcd.setFont(u8g2_font_logisoso16_tn);
    centered(44, buf);
    footer("OK: yes, pair   DOWN: no");
}

static void drawHybrid() {
    g_lcd.setFont(u8g2_font_6x10_tr);
    centered(12, "Phone-style login");
    const char* rt = hybrid::requestType();
    g_lcd.setFont(u8g2_font_5x7_tr);
    if (rt[0]) centered(24, rt);
    g_lcd.setFont(u8g2_font_7x13B_tr);
    centered(42, hybrid::stateText());
    footer("hold OK: cancel");
}

static void drawUnlockPrompt(const unlock::Prompt* p) {
    bool pairing = p->kind == unlock::PromptKind::Pair;
    g_lcd.setFont(u8g2_font_6x10_tr);
    g_lcd.drawBox(0, 0, W, 11);
    g_lcd.setDrawColor(0);
    centered(9, pairing ? "PAIR THIS PC?" : "UNLOCK PC?");
    g_lcd.setDrawColor(1);
    g_lcd.setFont(u8g2_font_7x13B_tr);
    centered(28, p->name);
    g_lcd.setFont(u8g2_font_5x7_tr);
    char via[24];
    snprintf(via, sizeof(via), "via %s", p->via);
    centered(40, via);
    if (pairing) centered(49, "Windows sign-in");
    footer(pairing ? "OK: pair   DOWN: cancel" : "OK: unlock   DOWN: deny");
}

static void drawApproval(const approval::Request* a) {
    g_lcd.setFont(u8g2_font_6x10_tr);
    g_lcd.drawBox(0, 0, W, 11);
    g_lcd.setDrawColor(0);
    centered(9, a->title);
    g_lcd.setDrawColor(1);
    g_lcd.setFont(u8g2_font_5x7_tr);
    centered(26, a->detail);
    centered(37, a->hint);
    uint32_t elapsed = millis() - a->startedMs;
    uint32_t left = elapsed < FIDO_USER_TIMEOUT_MS ? (FIDO_USER_TIMEOUT_MS - elapsed) / 1000 : 0;
    char t[16];
    snprintf(t, sizeof(t), "%lus", (unsigned long)left);
    g_lcd.drawStr(W - g_lcd.getStrWidth(t), 47, t);
    footer(a->needPin ? "OK: enter PIN   DOWN: deny" : "OK: allow   DOWN: deny");
}

static void draw() {
    g_lcd.clearBuffer();
    g_lcd.setDrawColor(1);
    uint32_t code;
    const CtapPrompt* p = ctap::prompt();

    if (ble::pairingPending(&code)) {
        drawPairing(code);
    } else if (const unlock::Prompt* up = unlock::prompt()) {
        drawUnlockPrompt(up);
    } else if (approval::pending() &&
               !(s_screen == Screen::PinEntry && s_pinPurpose == PinPurpose::Approval)) {
        drawApproval(approval::pending());
    } else if (p && !(s_screen == Screen::PinEntry && s_pinPurpose == PinPurpose::CtapUv)) {
        drawPrompt(p);
    } else if (s_screen == Screen::PinEntry) {
        drawPinEntry();
    } else if (hybrid::state() == hybrid::State::Connecting ||
               hybrid::state() == hybrid::State::Advertising ||
               hybrid::state() == hybrid::State::Failed) {
        drawHybrid();
    } else {
        switch (s_screen) {
            case Screen::Home: drawHome(); break;
            case Screen::Menu: list("Menu", MENU_ITEMS, MENU_COUNT, s_menuIndex, menuItemText); break;
            case Screen::Passkeys:
                list("Passkeys", nullptr, s_listCount ? s_listCount : 1, s_listIndex, passkeyItemText);
                break;
            case Screen::PasskeyDetail: drawPasskeyDetail(); break;
            case Screen::PinMenu: {
                static const char* items[] = {"Change PIN", "Remove PIN", "Back"};
                static const char* setItems[] = {"Set PIN", "Back"};
                if (settings::pinIsSet()) list("Device PIN", items, 3, s_listIndex);
                else list("Device PIN", setItems, 2, s_listIndex);
                break;
            }
            case Screen::Wifi: drawWifi(); break;
            case Screen::Portal: drawPortal(); break;
            case Screen::Bluetooth: drawBluetooth(); break;
            case Screen::Log: drawLog(); break;
            case Screen::Info: drawInfo(); break;
            case Screen::ConfirmReset: drawConfirmReset(); break;
            default: break;
        }
    }

    if (s_toast[0] && millis() < s_toastUntil) {
        g_lcd.setFont(u8g2_font_6x10_tr);
        int w = g_lcd.getStrWidth(s_toast) + 8;
        int x = (W - w) / 2;
        g_lcd.setDrawColor(0);
        g_lcd.drawBox(x, 22, w, 16);
        g_lcd.setDrawColor(1);
        g_lcd.drawFrame(x, 22, w, 16);
        g_lcd.drawStr(x + 4, 34, s_toast);
    } else {
        s_toast[0] = '\0';
    }
    g_lcd.sendBuffer();
}

// --- PIN entry ---------------------------------------------------------------

static void beginPin(PinPurpose purpose, Screen returnTo) {
    s_pinPurpose = purpose;
    s_pinReturn = returnTo;
    s_pinLen = 0;
    s_pinDigit = 0;
    memset(s_pin, 0, sizeof(s_pin));
    s_screen = Screen::PinEntry;
}

static void endPin(Screen next) {
    memset(s_pin, 0, sizeof(s_pin));
    s_pinLen = 0;
    s_screen = next;
}

static void submitPin() {
    s_pin[s_pinLen] = '\0';
    switch (s_pinPurpose) {
        case PinPurpose::CtapUv:
            if (ctap::userSubmitPin(s_pin)) endPin(Screen::Home);
            else {
                toast(settings::pinRetries() ? "Wrong PIN" : "PIN blocked");
                if (!ctap::prompt()) endPin(Screen::Home);
                else { s_pinLen = 0; s_pinDigit = 0; }
            }
            break;
        case PinPurpose::Approval:
            if (approval::submitPin(s_pin)) endPin(Screen::Home);
            else {
                toast(settings::pinRetries() ? "Wrong PIN" : "PIN blocked");
                if (!approval::pending()) endPin(Screen::Home);
                else { s_pinLen = 0; s_pinDigit = 0; }
            }
            break;
        case PinPurpose::SetNew:
            if (s_pinLen < FIDO_PIN_MIN_LEN) { toast("Min 4 digits"); return; }
            strlcpy(s_pinFirst, s_pin, sizeof(s_pinFirst));
            beginPin(PinPurpose::SetConfirm, s_pinReturn);
            break;
        case PinPurpose::SetConfirm:
            if (strcmp(s_pin, s_pinFirst) == 0 && settings::pinSet(s_pin)) {
                toast("PIN saved");
                logEvent("Device PIN set");
            } else {
                toast("PINs differ");
            }
            memset(s_pinFirst, 0, sizeof(s_pinFirst));
            endPin(Screen::PinMenu);
            break;
        case PinPurpose::ChangeOld:
            if (settings::pinVerify(s_pin)) beginPin(PinPurpose::SetNew, Screen::PinMenu);
            else { toast("Wrong PIN"); endPin(Screen::PinMenu); }
            break;
        case PinPurpose::RemoveOld:
            if (settings::pinVerify(s_pin)) {
                settings::pinClear();
                toast("PIN removed");
                logEvent("Device PIN removed");
            } else {
                toast("Wrong PIN");
            }
            endPin(Screen::PinMenu);
            break;
    }
}

static bool isPromptPin() {
    return s_pinPurpose == PinPurpose::CtapUv || s_pinPurpose == PinPurpose::Approval;
}

static void handlePinKey(Key k) {
    switch (k) {
        case Key::Up:   s_pinDigit = (s_pinDigit + 1) % 10; break;
        case Key::Down: s_pinDigit = (s_pinDigit + 9) % 10; break;
        case Key::Ok:
            if (s_pinLen < FIDO_PIN_MAX_LEN) {
                s_pin[s_pinLen++] = (char)('0' + s_pinDigit);
                s_pinDigit = 0;
            }
            break;
        case Key::UpLong:
        case Key::Left:
            if (s_pinLen > 0) {
                s_pinLen--;                          // backspace
            } else {
                if (s_pinPurpose == PinPurpose::CtapUv) ctap::userDeny();
                if (s_pinPurpose == PinPurpose::Approval) approval::deny();
                endPin(isPromptPin() ? Screen::Home : s_pinReturn);
            }
            break;
        case Key::OkLong:
            // Include the digit under the cursor if the user didn't press OK on it.
            if (s_pinLen < FIDO_PIN_MIN_LEN && s_pinLen < FIDO_PIN_MAX_LEN) {
                s_pin[s_pinLen++] = (char)('0' + s_pinDigit);
            }
            submitPin();
            break;
        case Key::DownLong:
            if (s_pinPurpose == PinPurpose::CtapUv) ctap::userDeny();
            if (s_pinPurpose == PinPurpose::Approval) approval::deny();
            endPin(isPromptPin() ? Screen::Home : s_pinReturn);
            break;
        default: break;
    }
}

// --- Input handling ----------------------------------------------------------

// OK on the code screen: type the code into the paired PC / phone.
static void typeCurrentCode() {
    if (!ble::keyboardEnabled()) { toast("Keyboard is off"); return; }
    time_t now = network::now();
    if (!now) { toast("Clock not set"); return; }
    TotpAccount a;
    if (!totp::get(s_totpIndex, &a)) return;
    char code[12];
    snprintf(code, sizeof(code), "%0*lu", a.digits, (unsigned long)totp::generate(a, now));
    memset(&a, 0, sizeof(a));
    int hosts = ble::typeText(code);
    memset(code, 0, sizeof(code));
    toast(hosts ? "Code typed" : "No keyboard host");
}

static void openMenuItem(int i) {
    switch (i) {
        case 0: reloadPasskeys(); s_listIndex = 0; s_screen = Screen::Passkeys; break;
        case 1:
            settings::setAutoApprove(!settings::autoApprove());
            logEvent("Auto-approve %s", settings::autoApprove() ? "ON" : "off");
            break;
        case 2: s_listIndex = 0; s_screen = Screen::PinMenu; break;
        case 3: s_screen = Screen::Wifi; break;
        case 4: s_portalSel = 0; s_screen = Screen::Portal; break;
        case 5: s_screen = Screen::Bluetooth; break;
        case 6: s_listIndex = 0; s_screen = Screen::Log; break;
        case 7: s_screen = Screen::Info; break;
        case 8: s_screen = Screen::ConfirmReset; break;
        default: s_screen = Screen::Home; break;
    }
}

static bool isBack(Key k) { return k == Key::Left || k == Key::OkLong || k == Key::Down; }

static void handleKey(Key k) {
    uint32_t code;
    // 1. Pairing confirmation
    if (ble::pairingPending(&code)) {
        if (k == Key::Ok) ble::pairingConfirm(true);
        else if (k == Key::Down || k == Key::Left) ble::pairingConfirm(false);
        return;
    }
    // 1b. PC pairing / unlock
    if (unlock::prompt()) {
        if (k == Key::Ok) unlock::userApprove();
        else if (k == Key::Down || k == Key::Left) unlock::userDeny();
        return;
    }
    // 1c. Backup / restore / web-session confirmation
    if (approval::pending()) {
        if (s_screen == Screen::PinEntry && s_pinPurpose == PinPurpose::Approval) {
            handlePinKey(k);
            return;
        }
        if (k == Key::Down || k == Key::Left) approval::deny();
        else if (k == Key::Ok) {
            if (approval::pending()->needPin) beginPin(PinPurpose::Approval, s_screen);
            else approval::approve();
        }
        return;
    }
    if (s_screen == Screen::PinEntry && s_pinPurpose == PinPurpose::Approval) endPin(Screen::Home);
    // 2. FIDO prompt
    const CtapPrompt* p = ctap::prompt();
    if (p) {
        if (s_screen == Screen::PinEntry && s_pinPurpose == PinPurpose::CtapUv) {
            handlePinKey(k);
            return;
        }
        if (k == Key::Down || k == Key::Left) { ctap::userDeny(); return; }
        if (p->kind == PromptKind::Reset) {
            if (k == Key::OkLong) ctap::userApprove();
            return;
        }
        if (k == Key::Ok) {
            if (p->needPin) beginPin(PinPurpose::CtapUv, s_screen);
            else ctap::userApprove();
        }
        return;
    }
    if (s_screen == Screen::PinEntry && s_pinPurpose == PinPurpose::CtapUv) {
        endPin(Screen::Home);   // prompt went away (timeout / cancel)
    }
    // 3. Hybrid session in progress
    if (hybrid::state() == hybrid::State::Connecting || hybrid::state() == hybrid::State::Advertising) {
        if (k == Key::OkLong) hybrid::stop("cancelled on device");
        return;
    }

    switch (s_screen) {
        case Screen::Home: {
            int n = totp::count();
            if (k == Key::Up && n) s_totpIndex = (s_totpIndex + n - 1) % n;
            else if (k == Key::Down && n) s_totpIndex = (s_totpIndex + 1) % n;
            else if (k == Key::OkLong || k == Key::Right) { s_menuIndex = 0; s_screen = Screen::Menu; }
            else if (k == Key::Ok && n) typeCurrentCode();
            break;
        }
        case Screen::Menu:
            if (k == Key::Up) s_menuIndex = (s_menuIndex + MENU_COUNT - 1) % MENU_COUNT;
            else if (k == Key::Down) s_menuIndex = (s_menuIndex + 1) % MENU_COUNT;
            else if (k == Key::Ok || k == Key::Right) openMenuItem(s_menuIndex);
            else if (k == Key::OkLong || k == Key::Left) s_screen = Screen::Home;
            break;
        case Screen::Passkeys:
            if (k == Key::Up && s_listCount) s_listIndex = (s_listIndex + s_listCount - 1) % s_listCount;
            else if (k == Key::Down && s_listCount) s_listIndex = (s_listIndex + 1) % s_listCount;
            else if ((k == Key::Ok || k == Key::Right) && s_listCount) s_screen = Screen::PasskeyDetail;
            else if (k == Key::OkLong || k == Key::Left || (k == Key::Ok && !s_listCount)) s_screen = Screen::Menu;
            break;
        case Screen::PasskeyDetail:
            if (k == Key::OkLong) {
                creds::residentDelete(s_listSlots[s_listIndex]);
                logEvent("Passkey deleted");
                toast("Deleted");
                reloadPasskeys();
                s_screen = Screen::Passkeys;
            } else if (k == Key::Down || k == Key::Left || k == Key::Ok) {
                s_screen = Screen::Passkeys;
            }
            break;
        case Screen::PinMenu: {
            int n = settings::pinIsSet() ? 3 : 2;
            if (k == Key::Up) s_listIndex = (s_listIndex + n - 1) % n;
            else if (k == Key::Down) s_listIndex = (s_listIndex + 1) % n;
            else if (k == Key::OkLong || k == Key::Left) s_screen = Screen::Menu;
            else if (k == Key::Ok) {
                if (!settings::pinIsSet()) {
                    if (s_listIndex == 0) beginPin(PinPurpose::SetNew, Screen::PinMenu);
                    else s_screen = Screen::Menu;
                } else if (s_listIndex == 0) beginPin(PinPurpose::ChangeOld, Screen::PinMenu);
                else if (s_listIndex == 1) beginPin(PinPurpose::RemoveOld, Screen::PinMenu);
                else s_screen = Screen::Menu;
            }
            break;
        }
        case Screen::PinEntry:
            handlePinKey(k);
            break;
        case Screen::Wifi:
            if (k == Key::Ok) { network::reconnectSoon(); toast("Reconnecting"); }
            else if (isBack(k)) s_screen = Screen::Menu;
            break;
        case Screen::Portal:
            if (k == Key::Up) s_portalSel = (s_portalSel + 3) % 4;
            else if (k == Key::Down || k == Key::Right) s_portalSel = (s_portalSel + 1) % 4;
            else if (k == Key::OkLong || k == Key::Left) s_screen = Screen::Menu;
            else if (k == Key::Ok) {
                if (s_portalSel == 3) { s_screen = Screen::Menu; break; }
                if (!portal::haveCredentials()) { toast("No credentials"); break; }
                if (s_portalSel == 0) { portal::loginNow(); toast("Logging in..."); }
                else if (s_portalSel == 1) { portal::logout(); toast("Logging out..."); }
                else {
                    portal::setEnabled(!portal::enabled());
                    toast(portal::enabled() ? "Auto-login ON" : "Auto-login off");
                }
            }
            break;
        case Screen::Bluetooth:
            if (k == Key::OkLong) { ble::forgetBonds(); logEvent("BLE bonds cleared"); toast("Forgotten"); }
            else if (k == Key::Ok) {
                settings::setKeyboard(!settings::keyboard());
                logEvent("BT keyboard %s", settings::keyboard() ? "ON" : "off");
                toast("Rebooting...");
                draw();
                logFlush();
                delay(800);
                ESP.restart();
            }
            else if (k == Key::Down || k == Key::Left) s_screen = Screen::Menu;
            break;
        case Screen::Log:
            if (k == Key::Up) s_listIndex++;
            else if (k == Key::Down && s_listIndex > 0) s_listIndex--;
            else if (k == Key::Ok || k == Key::OkLong || k == Key::Left) s_screen = Screen::Menu;
            break;
        case Screen::Info:
            if (k != Key::None) s_screen = Screen::Menu;
            break;
        case Screen::ConfirmReset:
            if (k == Key::OkLong) {
                settings::resetFido();
                creds::residentWipe();
                logEvent("Passkeys reset on device");
                toast("Reset done");
                s_screen = Screen::Menu;
            } else if (k == Key::Down || k == Key::Left || k == Key::Ok) {
                s_screen = Screen::Menu;
            }
            break;
    }
}

// --- Public ------------------------------------------------------------------

void init() {
    Wire.begin(PIN_SDA, PIN_SCL);
    Wire.setClock(400000);
    g_lcd.begin();
    g_lcd.setContrast(200);
    buttons::init();
    s_lastInput = millis();
}

void bootStatus(const char* line) {
    g_lcd.clearBuffer();
    g_lcd.setFont(u8g2_font_7x13B_tr);
    centered(20, FW_NAME);
    g_lcd.setFont(u8g2_font_5x7_tr);
    centered(32, "v" FW_VERSION);
    centered(52, line);
    g_lcd.sendBuffer();
}

void otaProgress(unsigned done, unsigned total) {
    g_lcd.clearBuffer();
    g_lcd.setFont(u8g2_font_6x10_tr);
    centered(20, "Firmware update");
    g_lcd.drawFrame(4, 30, W - 8, 10);
    g_lcd.drawBox(4, 30, total ? (uint32_t)(W - 8) * done / total : 0, 10);
    g_lcd.sendBuffer();
}

void loop() {
    Key k = buttons::poll();
    bool attention = ctap::prompt() || ble::pairingPending(nullptr) || unlock::prompt() || approval::pending();

    if (k != Key::None) {
        s_lastInput = millis();
        s_dirty = true;
        if (s_asleep) {
            s_asleep = false;
            g_lcd.setPowerSave(0);
            k = Key::None;   // first press only wakes the screen
        }
    }
    if (attention && s_asleep) {
        s_asleep = false;
        g_lcd.setPowerSave(0);
        s_lastInput = millis();
    }
    if (attention) s_lastInput = millis();

    if (k != Key::None) handleKey(k);

    if (DISPLAY_SLEEP_MS && !s_asleep && millis() - s_lastInput > DISPLAY_SLEEP_MS) {
        s_asleep = true;
        s_screen = Screen::Home;
        g_lcd.setPowerSave(1);
    }
    if (s_asleep) return;

    if (s_dirty || millis() - s_lastDraw > 250) {
        s_dirty = false;
        s_lastDraw = millis();
        draw();
    }
}

}  // namespace ui
