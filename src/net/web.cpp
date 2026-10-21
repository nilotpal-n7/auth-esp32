#include "net/web.h"
#include "config.h"
#include "core/approval.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "fido/credentials.h"
#include "net/network.h"
#include "net/portal.h"
#include "net/web_page.h"
#include "totp/totp.h"
#include "transport/ble.h"
#include "transport/hybrid.h"
#include "util/codec.h"

#include <ESPmDNS.h>
#include <WebServer.h>
#include <WiFi.h>

namespace web {

#define WEB_SESSIONS        4
#define WEB_SESSION_MS      (12UL * 3600UL * 1000UL)

struct Session {
    char     token[33];
    uint32_t ip;
    uint32_t createdMs;
    bool     used;
};

static WebServer s_http(80);
static bool      s_started = false;
static Session   s_sessions[WEB_SESSIONS];

// One "allow this browser?" request at a time.
static struct {
    uint32_t id;
    uint32_t ip;
    uint8_t  state;      // 0 none, 1 waiting, 2 allowed, 3 denied
    int      slot;       // session created on approval
} s_pend;

// --- Helpers -------------------------------------------------------------------

static uint32_t clientIp() { return (uint32_t)s_http.client().remoteIP(); }

static void jstr(String& o, const char* s) {
    o += '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
        else o += (char)c;
    }
    o += '"';
}

static void sendJson(int code, const String& body) {
    s_http.sendHeader("Cache-Control", "no-store");
    s_http.send(code, "application/json", body);
}

static void sendError(int code, const char* msg) {
    String o = "{\"error\":";
    jstr(o, msg);
    o += '}';
    sendJson(code, o);
}

static int findSession() {
    String cookie = s_http.header("Cookie");
    int at = cookie.indexOf("ak=");
    if (at < 0) return -1;
    String tok = cookie.substring(at + 3, at + 3 + 32);
    if (tok.length() != 32) return -1;
    uint32_t ip = clientIp();
    for (int i = 0; i < WEB_SESSIONS; i++) {
        Session& s = s_sessions[i];
        if (!s.used) continue;
        if (millis() - s.createdMs > WEB_SESSION_MS) { s.used = false; continue; }
        if (s.ip == ip && crypto::equal((const uint8_t*)s.token, (const uint8_t*)tok.c_str(), 32)) return i;
    }
    return -1;
}

static bool authed() { return findSession() >= 0; }

// Management calls: a session cookie, and for changes the X-AuthKey header.
static bool guard(bool change) {
    if (change && s_http.header("X-AuthKey") != "1") { sendError(403, "missing X-AuthKey header"); return false; }
    if (!authed()) { sendError(401, "locked"); return false; }
    return true;
}

static int newSession(uint32_t ip) {
    int slot = 0;
    for (int i = 0; i < WEB_SESSIONS; i++) {
        if (!s_sessions[i].used) { slot = i; break; }
        if (s_sessions[i].createdMs < s_sessions[slot].createdMs) slot = i;   // replace the oldest
    }
    uint8_t raw[16];
    crypto::random(raw, sizeof(raw));
    hexEncode(raw, sizeof(raw), s_sessions[slot].token);
    crypto::wipe(raw, sizeof(raw));
    s_sessions[slot].ip = ip;
    s_sessions[slot].createdMs = millis();
    s_sessions[slot].used = true;
    return slot;
}

// --- Handlers ------------------------------------------------------------------

static void handlePage() {
    s_http.sendHeader("Cache-Control", "no-store");
    s_http.send_P(200, "text/html; charset=utf-8", WEB_PAGE, strlen(WEB_PAGE));
}

static void handleStatus() {
    bool auth = authed();
    char clock[8];
    network::localClock(clock, sizeof(clock));
    String o;
    o.reserve(700);
    o += "{\"fw\":";              jstr(o, FW_VERSION);
    o += ",\"uptime\":";          o += millis() / 1000;
    o += ",\"heap\":";            o += ESP.getFreeHeap();
    o += ",\"clock\":";           jstr(o, clock);
    o += ",\"auth\":";            o += auth ? "true" : "false";
    o += ",\"wifi\":{\"ssid\":";  jstr(o, network::ssid());
    o += ",\"ip\":";              jstr(o, network::ip().c_str());
    o += ",\"rssi\":";            o += network::connected() ? WiFi.RSSI() : 0;
    o += "},\"campus\":{\"have\":"; o += portal::haveCredentials() ? "true" : "false";
    o += ",\"state\":";           jstr(o, portal::stateStr());
    o += ",\"online\":";          o += portal::online() ? "true" : "false";
    o += ",\"paused\":";          o += portal::paused() ? "true" : "false";
    o += ",\"auto\":";            o += portal::enabled() ? "true" : "false";
    o += ",\"owns\":";            o += portal::ownsSession() ? "true" : "false";
    o += ",\"next\":";            o += portal::secondsToNext();
    o += ",\"logins\":";          o += portal::logins();
    o += ",\"refreshes\":";       o += portal::keepalives();
    o += ",\"last\":";            jstr(o, portal::lastResult());
    if (auth) { o += ",\"user\":"; jstr(o, portal::user()); }
    o += "},\"bt\":{\"links\":";  o += ble::linkCount();
    o += ",\"bonds\":";           o += ble::bondCount();
    o += ",\"keyboard\":";        o += ble::keyboardEnabled() ? "true" : "false";
    o += ",\"keyboardHosts\":";   o += ble::keyboardHosts();
    o += "},\"totp\":";           o += totp::count();
    o += ",\"passkeys\":";        o += creds::residentCount();
    o += ",\"passkeyCapacity\":"; o += creds::residentCapacity();
    o += ",\"hybrid\":";          jstr(o, hybrid::state() == hybrid::State::Idle ? "" : hybrid::stateText());
    o += '}';
    sendJson(200, o);
}

static void onWebApproval(bool approved, void*) {
    if (s_pend.state != 1) return;
    if (approved) {
        s_pend.slot = newSession(s_pend.ip);
        s_pend.state = 2;
        logEvent("Web access allowed");
    } else {
        s_pend.state = 3;
    }
}

// POST /api/session: ask on the device. GET /api/session?id=N: poll; once
// allowed, the response sets the session cookie.
static void handleSessionStart() {
    if (s_http.header("X-AuthKey") != "1") { sendError(403, "missing X-AuthKey header"); return; }
    uint32_t ip = clientIp();
    if (!(s_pend.state == 1 && s_pend.ip == ip)) {
        char who[24];
        snprintf(who, sizeof(who), "from %s", IPAddress(ip).toString().c_str());
        if (!approval::ask("ALLOW WEB ACCESS?", who, "this browser, 12 hours", false, onWebApproval, nullptr)) {
            sendError(409, "the device is busy; try again");
            return;
        }
        crypto::random((uint8_t*)&s_pend.id, sizeof(s_pend.id));
        s_pend.id &= 0x7FFFFFFF;
        s_pend.ip = ip;
        s_pend.state = 1;
    }
    sendJson(200, String("{\"id\":") + s_pend.id + "}");
}

static void handleSessionPoll() {
    uint32_t id = (uint32_t)strtoul(s_http.arg("id").c_str(), nullptr, 10);
    if (s_pend.state == 0 || id != s_pend.id || clientIp() != s_pend.ip) { sendJson(200, "{\"state\":\"expired\"}"); return; }
    if (s_pend.state == 1) {
        sendJson(200, approval::pending() ? "{\"state\":\"waiting\"}" : "{\"state\":\"expired\"}");
        if (!approval::pending()) s_pend.state = 0;
        return;
    }
    if (s_pend.state == 2) {
        String c = String("ak=") + s_sessions[s_pend.slot].token + "; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict";
        s_http.sendHeader("Set-Cookie", c);
        sendJson(200, "{\"state\":\"allowed\"}");
    } else {
        sendJson(200, "{\"state\":\"denied\"}");
    }
    s_pend.state = 0;
}

static void handleLogout() {
    if (s_http.header("X-AuthKey") != "1") { sendError(403, "missing X-AuthKey header"); return; }
    int i = findSession();
    if (i >= 0) s_sessions[i].used = false;
    s_http.sendHeader("Set-Cookie", "ak=; Path=/; Max-Age=0");
    sendJson(200, "{\"ok\":true}");
}

static void handleLog() {
    if (!guard(false)) return;
    String o = "{\"lines\":[";
    for (int i = 0; i < logCount(); i++) {
        if (i) o += ',';
        jstr(o, logLine(i));
    }
    o += "]}";
    sendJson(200, o);
}

static void handlePortal() {
    if (!guard(true)) return;
    String what = s_http.arg("do");
    if (!portal::haveCredentials()) { sendError(400, "no IITG credentials in .env"); return; }
    if (what == "login") portal::loginNow();
    else if (what == "logout") portal::logout();
    else if (what == "on" || what == "off") portal::setEnabled(what == "on");
    else { sendError(400, "do=login|logout|on|off"); return; }
    sendJson(200, "{\"ok\":true}");
}

static void handleTotpList() {
    if (!guard(false)) return;
    String o = "{\"accounts\":[";
    TotpAccount a;
    for (int i = 0; i < totp::count(); i++) {
        if (!totp::get(i, &a)) continue;
        if (i) o += ',';
        o += "{\"i\":"; o += i;
        o += ",\"name\":"; jstr(o, a.name);
        o += ",\"digits\":"; o += a.digits;
        o += ",\"period\":"; o += a.period;
        o += ",\"algo\":"; o += a.algo;
        o += '}';
    }
    crypto::wipe(&a, sizeof(a));
    o += "]}";
    sendJson(200, o);
}

static void handleTotpAdd() {
    if (!guard(true)) return;
    String uri = s_http.arg("plain");
    uri.trim();
    TotpAccount a;
    bool ok = totp::parseUri(uri.c_str(), &a);
    int i = ok ? totp::add(a) : -1;
    crypto::wipe(&a, sizeof(a));
    for (size_t k = 0; k < uri.length(); k++) uri[k] = 0;   // held the secret
    if (!ok) { sendError(400, "not a valid otpauth://totp/ link"); return; }
    if (i < 0) { sendError(507, "TOTP storage full"); return; }
    logEvent("TOTP added (web)");
    sendJson(200, String("{\"ok\":true,\"i\":") + i + "}");
}

static void handleTotpDelete() {
    if (!guard(true)) return;
    if (!totp::remove(s_http.arg("i").toInt())) { sendError(404, "no such account"); return; }
    logEvent("TOTP deleted (web)");
    sendJson(200, "{\"ok\":true}");
}

static void handlePasskeyList() {
    if (!guard(false)) return;
    String o = "{\"passkeys\":[";
    ResidentCredential c;
    bool first = true;
    for (int i = 0; i < creds::residentCapacity(); i++) {
        if (!creds::residentGet(i, &c)) continue;
        if (!first) o += ',';
        first = false;
        o += "{\"slot\":"; o += i;
        o += ",\"rp\":"; jstr(o, c.rpId);
        o += ",\"user\":"; jstr(o, c.userName);
        o += ",\"display\":"; jstr(o, c.displayName);
        o += ",\"order\":"; o += c.created;
        o += '}';
    }
    o += "]}";
    sendJson(200, o);
}

static void handlePasskeyDelete() {
    if (!guard(true)) return;
    if (!creds::residentDelete(s_http.arg("slot").toInt())) { sendError(404, "no such passkey"); return; }
    logEvent("Passkey deleted (web)");
    sendJson(200, "{\"ok\":true}");
}

static void handleHybrid() {
    if (!guard(true)) return;
    String qr = s_http.arg("plain");
    qr.trim();
    if (qr == "stop") { hybrid::stop("stopped from web"); sendJson(200, "{\"ok\":true}"); return; }
    if (!hybrid::start(qr.c_str())) { sendError(400, "not a passkey QR (FIDO:/...)"); return; }
    sendJson(200, "{\"ok\":true}");
}

static void start() {
    static const char* headers[] = {"Cookie", "X-AuthKey"};
    s_http.collectHeaders(headers, 2);
    s_http.on("/", HTTP_GET, handlePage);
    s_http.on("/api/status", HTTP_GET, handleStatus);
    s_http.on("/api/session", HTTP_POST, handleSessionStart);
    s_http.on("/api/session", HTTP_GET, handleSessionPoll);
    s_http.on("/api/logout", HTTP_POST, handleLogout);
    s_http.on("/api/log", HTTP_GET, handleLog);
    s_http.on("/api/portal", HTTP_POST, handlePortal);
    s_http.on("/api/totp", HTTP_GET, handleTotpList);
    s_http.on("/api/totp/add", HTTP_POST, handleTotpAdd);
    s_http.on("/api/totp/delete", HTTP_POST, handleTotpDelete);
    s_http.on("/api/passkeys", HTTP_GET, handlePasskeyList);
    s_http.on("/api/passkeys/delete", HTTP_POST, handlePasskeyDelete);
    s_http.on("/api/hybrid", HTTP_POST, handleHybrid);
    s_http.onNotFound([]() { sendError(404, "not found"); });
    s_http.begin();
    MDNS.addService("http", "tcp", 80);
    s_started = true;
    logf("WEB", "management page at http://%s/ (authkey-esp32.local)", network::ip().c_str());
}

void loop() {
    if (!s_started) {
        if (network::connected()) start();
        return;
    }
    s_http.handleClient();
}

}  // namespace web
