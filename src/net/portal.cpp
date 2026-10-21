#include "net/portal.h"
#include "net/portal_ca.h"
#include "net/network.h"
#include "config.h"
#include "core/log.h"
#include "core/settings.h"
#include "fido/ctap2.h"
#include "transport/hybrid.h"

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ctype.h>
#include <stdarg.h>

// Never log or print the request body: it carries the IITG password.

namespace portal {

enum class St : uint8_t { Offline, LoggingIn, Online, Limit, Failed };
enum class Res : uint8_t { Ok, OkNoMagic, Limit, Rejected, Unknown, Network };

static St       s_state = St::Offline;
static char     s_magic[40] = "";       // session id for /keepalive and /logout
static char     s_result[48] = "";      // last outcome, shown on screen
static char     s_lastEvent[64] = "";   // de-duplicates the event log
static uint32_t s_next = 0;             // next probe / retry (millis)
static uint32_t s_nextKeep = 0;         // next keepalive
static uint32_t s_nextAdopt = 0;        // next attempt to take over a session we don't own
static int      s_rejects = 0;          // consecutive "wrong credentials" replies
static int      s_netFails = 0;         // consecutive network / unknown failures
static int      s_logins = 0;
static int      s_keeps = 0;
static bool     s_force = false;        // "login now" requested
static bool     s_wantLogout = false;   // "logout" requested
static bool     s_paused = false;       // logged out by hand

static char s_buf[6144];                // one HTTP response at a time

// --- small helpers -----------------------------------------------------------

static void setResult(const char* r) { strlcpy(s_result, r, sizeof(s_result)); }

static void event(const char* fmt, ...) {
    char msg[64];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (strcmp(msg, s_lastEvent) == 0) return;   // only log changes
    strlcpy(s_lastEvent, msg, sizeof(s_lastEvent));
    logEvent("%s", msg);
}

static void urlEncode(const char* in, char* out, size_t cap) {
    static const char* hex = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char* p = (const unsigned char*)in; *p && o + 4 < cap; p++) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') {
            out[o++] = *p;
        } else {
            out[o++] = '%'; out[o++] = hex[*p >> 4]; out[o++] = hex[*p & 15];
        }
    }
    out[o] = '\0';
}

static const char* findCI(const char* hay, const char* needle) {
    size_t n = strlen(needle);
    for (; *hay; hay++)
        if (strncasecmp(hay, needle, n) == 0) return hay;
    return nullptr;
}

// Copies the alphanumeric token right after `key` (e.g. "keepalive?").
static bool tokenAfter(const char* buf, const char* key, char* out, size_t cap) {
    const char* p = strstr(buf, key);
    if (!p) return false;
    p += strlen(key);
    size_t o = 0;
    while (*p && isalnum((unsigned char)*p) && o + 1 < cap) out[o++] = *p++;
    out[o] = '\0';
    return o > 0;
}

// value="..." of the <input> whose name attribute is `nameAttr` (e.g. name="magic").
static bool inputValue(const char* buf, const char* nameAttr, char* out, size_t cap) {
    const char* p = strstr(buf, nameAttr);
    if (!p) return false;
    const char* end = strchr(p, '>');
    const char* v = strstr(p, "value=\"");
    if (!v || (end && v > end)) return false;
    v += 7;
    size_t o = 0;
    while (*v && *v != '"' && o + 1 < cap) out[o++] = *v++;
    out[o] = '\0';
    return true;
}

static const char* bodyOf() {
    const char* b = strstr(s_buf, "\r\n\r\n");
    return b ? b + 4 : s_buf;
}

static void titleOf(char* out, size_t cap) {
    out[0] = '\0';
    const char* t = findCI(s_buf, "<title>");
    if (!t) return;
    t += 7;
    while (*t == ' ') t++;
    size_t o = 0;
    while (*t && *t != '<' && o + 1 < cap) out[o++] = *t++;
    while (o && out[o - 1] == ' ') o--;
    out[o] = '\0';
}

// Visible text of the page body (tags and <style> stripped, spaces collapsed).
static void pageText(char* out, size_t cap) {
    const char* p = findCI(s_buf, "<body");
    if (!p) p = bodyOf();
    size_t o = 0;
    bool space = true;
    while (*p && o + 1 < cap) {
        if (*p == '<') {
            if (!strncasecmp(p, "<style", 6)) {
                const char* e = findCI(p, "</style>");
                p = e ? e + 8 : p + strlen(p);
                continue;
            }
            const char* e = strchr(p, '>');
            p = e ? e + 1 : p + strlen(p);
            if (!space) { out[o++] = ' '; space = true; }
            continue;
        }
        if (isspace((unsigned char)*p) || !strncmp(p, "&nbsp;", 6)) {
            p += (*p == '&') ? 6 : 1;
            if (!space) { out[o++] = ' '; space = true; }
            continue;
        }
        out[o++] = *p++;
        space = false;
    }
    out[o] = '\0';
}

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
static long daysFromCivil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (long)doe - 719468;
}

// NTP can be blocked while logged out: take the clock from the HTTP Date
// header ("Date: Wed, 21 Oct 2026 09:11:43 GMT") so TOTP and TLS still work.
static void clockFromDateHeader() {
    if (network::timeValid()) return;
    const char* d = findCI(s_buf, "\nDate: ");
    if (!d) return;
    static const char* months = "JanFebMarAprMayJunJulAugSepOctNovDec";
    int day, year, hh, mm, ss;
    char mon[4];
    if (sscanf(d + 7, "%*3s, %d %3s %d %d:%d:%d", &day, mon, &year, &hh, &mm, &ss) != 6) return;
    const char* mp = strstr(months, mon);
    if (!mp) return;
    unsigned month = (unsigned)((mp - months) / 3 + 1);
    time_t t = (time_t)daysFromCivil(year, month, day) * 86400 + hh * 3600 + mm * 60 + ss;
    network::setTimeUtc(t);
    logf("PORTAL", "clock set from HTTP Date header (NTP unreachable)");
}

// Sends one request and reads the whole response (headers + body) into s_buf.
// Returns the HTTP status, 0 for a reply that isn't HTTP, -1 if no connection.
static int fetch(WiFiClient& c, WiFiClientSecure* tls, const char* host, uint16_t port,
                 const char* method, const char* path, const char* body, const char* extra) {
    if (!c.connect(host, port)) {
        if (tls) {
            char err[80] = "";
            tls->lastError(err, sizeof(err));
            logf("PORTAL", "TLS connect to %s:%u failed: %s", host, port, err);
        } else {
            logf("PORTAL", "connect to %s:%u failed", host, port);
        }
        return -1;
    }
    c.printf("%s %s HTTP/1.1\r\nHost: %s\r\n"
             "User-Agent: Mozilla/5.0 (AuthKey-ESP32)\r\n"
             "Accept: text/html,*/*\r\nConnection: close\r\n", method, path, host);
    if (extra) c.print(extra);
    if (body) {
        c.printf("Content-Type: application/x-www-form-urlencoded\r\n"
                 "Content-Length: %u\r\n", (unsigned)strlen(body));
    }
    c.print("\r\n");
    if (body) c.print(body);

    size_t n = 0;
    uint32_t deadline = millis() + 10000;
    while ((int32_t)(millis() - deadline) < 0 && n + 1 < sizeof(s_buf)) {
        while (c.available() && n + 1 < sizeof(s_buf)) {
            s_buf[n++] = (char)c.read();
            deadline = millis() + 3000;
        }
        if (!c.connected() && !c.available()) break;
        delay(5);
    }
    s_buf[n] = '\0';
    c.stop();
    return (n >= 12 && !strncmp(s_buf, "HTTP/1.", 7)) ? atoi(s_buf + 9) : 0;
}

static int portalRequest(const char* method, const char* path, const char* body, const char* extra) {
    WiFiClientSecure c;
    c.setCACert(PORTAL_ROOT_CA);   // the portal's real cert is verified: the password stays private
    c.setHandshakeTimeout(12);
    return fetch(c, &c, PORTAL_HOST, PORTAL_PORT, method, path, body, extra);
}

// --- portal operations -------------------------------------------------------

enum class Probe : uint8_t { Online, Portal, Error };

static Probe probe() {
    WiFiClient c;
    int st = fetch(c, nullptr, PORTAL_PROBE_HOST, 80, "GET", PORTAL_PROBE_PATH, nullptr, nullptr);
    if (st <= 0) return Probe::Error;
    clockFromDateHeader();
    const char* b = bodyOf();
    while (*b && isspace((unsigned char)*b)) b++;
    if (st == 200 && !strncmp(b, PORTAL_PROBE_OK, strlen(PORTAL_PROBE_OK))) return Probe::Online;
    logf("PORTAL", "probe intercepted (HTTP %d): not logged in", st);
    return Probe::Portal;
}

static Res login() {
    // 1. A fresh login form (works logged in or out) carries the one-time magic.
    int st = portalRequest("GET", "/login?", nullptr, nullptr);
    if (st <= 0) { setResult("portal unreachable"); return Res::Network; }
    clockFromDateHeader();
    char magic[40], redir[160], title[48];
    titleOf(title, sizeof(title));
    if (!inputValue(s_buf, "name=\"magic\"", magic, sizeof(magic)) || !magic[0]) {
        logf("PORTAL", "login page HTTP %d has no form (title '%s')", st, title);
        setResult("no login form");
        return Res::Unknown;
    }
    if (!inputValue(s_buf, "name=\"4Tredir\"", redir, sizeof(redir)) || !redir[0])
        snprintf(redir, sizeof(redir), "https://%s:%d/login?", PORTAL_HOST, PORTAL_PORT);
    logf("PORTAL", "login form OK (HTTP %d); signing in as %s", st, SECRET_IITG_USER);

    // 2. Post it, like the browser does.
    char eRedir[200], eUser[96], ePass[200], body[560], hdr[200];
    urlEncode(redir, eRedir, sizeof(eRedir));
    urlEncode(SECRET_IITG_USER, eUser, sizeof(eUser));
    urlEncode(SECRET_IITG_PASS, ePass, sizeof(ePass));
    snprintf(body, sizeof(body), "4Tredir=%s&magic=%s&username=%s&password=%s",
             eRedir, magic, eUser, ePass);
    snprintf(hdr, sizeof(hdr), "Referer: https://%s:%d/login?\r\nOrigin: https://%s:%d\r\n",
             PORTAL_HOST, PORTAL_PORT, PORTAL_HOST, PORTAL_PORT);
    st = portalRequest("POST", "/", body, hdr);
    memset(body, 0, sizeof(body));
    memset(ePass, 0, sizeof(ePass));
    if (st <= 0) { setResult("no reply to login"); return Res::Network; }

    // 3. Success: the reply leads to /keepalive?<magic>.
    char m[40];
    if (tokenAfter(s_buf, "keepalive?", m, sizeof(m))) {
        strlcpy(s_magic, m, sizeof(s_magic));
        logf("PORTAL", "logged in; session refresh link received");
        return Res::Ok;
    }

    char text[160];
    titleOf(title, sizeof(title));
    pageText(text, sizeof(text));
    logf("PORTAL", "login reply HTTP %d, title '%s': %s", st, title, text);
    if (findCI(text, "limit") || findCI(text, "exceed") || findCI(text, "maximum") ||
        findCI(text, "concurrent") || findCI(text, "too many")) {
        setResult("session limit reached");
        return Res::Limit;
    }
    if (findCI(text, "fail") || findCI(text, "invalid") || findCI(text, "incorrect") ||
        findCI(text, "denied") || findCI(text, "wrong") || findCI(text, "not match")) {
        setResult("rejected: check password");
        return Res::Rejected;
    }
    // Accepted without a refresh link? Then the internet simply works now.
    if (probe() == Probe::Online) {
        setResult("logged in (no refresh link)");
        return Res::OkNoMagic;
    }
    setResult("unexpected login reply");
    return Res::Unknown;
}

static bool keepalive() {
    char path[64];
    snprintf(path, sizeof(path), "/keepalive?%s", s_magic);
    int st = portalRequest("GET", path, nullptr, nullptr);
    if (st == 200 && (strstr(s_buf, "Authentication Refresh") || findCI(s_buf, "logged in"))) {
        tokenAfter(s_buf, "keepalive?", s_magic, sizeof(s_magic));   // in case it rotated
        s_keeps++;
        logf("PORTAL", "session refreshed (#%d)", s_keeps);
        return true;
    }
    logf("PORTAL", "refresh failed (HTTP %d): session ended", st);
    s_magic[0] = '\0';
    return false;
}

static void doLogout() {
    if (!s_magic[0] && login() == Res::Ok) {
        logf("PORTAL", "took over the session to log it out");
    }
    s_paused = true;
    s_state = St::Offline;
    if (!s_magic[0]) {
        setResult("paused (no session to end)");
        event("Portal: paused");
        return;
    }
    char path[64];
    snprintf(path, sizeof(path), "/logout?%s", s_magic);
    int st = portalRequest("GET", path, nullptr, nullptr);
    s_magic[0] = '\0';
    logf("PORTAL", "logout HTTP %d", st);
    setResult("logged out");
    event("Portal: logged out");
}

static uint32_t netBackoffMs() {
    uint32_t s = (uint32_t)PORTAL_RETRY_SECS << (s_netFails < 4 ? s_netFails : 4);   // 30 s .. 8 min
    return (s > 300 ? 300 : s) * 1000UL;
}

static void doLogin(uint32_t now, bool manual) {
    s_state = St::LoggingIn;
    Res r = login();
    switch (r) {
        case Res::Ok:
        case Res::OkNoMagic:
            s_state = St::Online;
            s_rejects = s_netFails = 0;
            s_paused = false;
            s_logins++;
            s_nextKeep = now + (uint32_t)PORTAL_KEEPALIVE_SECS * 1000UL;
            s_next = now + (uint32_t)PORTAL_PROBE_SECS * 1000UL;
            if (r == Res::Ok) setResult("logged in");
            event("Portal: logged in (%s)", SECRET_IITG_USER);
            break;
        case Res::Limit:   // wait for a slot to free up, then log in again by itself
            s_state = St::Limit;
            s_next = now + (uint32_t)PORTAL_LIMIT_RETRY_SECS * 1000UL;
            event("Portal: session limit, retrying");
            break;
        case Res::Rejected:
            s_rejects++;
            s_state = St::Failed;
            s_next = now + (s_rejects >= PORTAL_MAX_FAILS ? (uint32_t)PORTAL_CRED_BACKOFF_SECS
                                                          : (uint32_t)PORTAL_RETRY_SECS) * 1000UL;
            event("Portal: login rejected");
            break;
        default:
            s_netFails++;
            s_state = St::Failed;
            s_next = now + netBackoffMs();
            event("Portal: %s", s_result);
            break;
    }
    if (manual && s_state != St::Online) logf("PORTAL", "manual login: %s", s_result);
}

// --- public API --------------------------------------------------------------

bool haveCredentials() { return SECRET_IITG_USER[0] && SECRET_IITG_PASS[0]; }
bool enabled() { return settings::portalAuto(); }
void setEnabled(bool on) {
    settings::setPortalAuto(on);
    logEvent("Portal auto-login %s", on ? "ON" : "off");
    s_next = 0;
}
bool paused() { return s_paused; }
bool online() { return s_state == St::Online; }
bool ownsSession() { return s_magic[0] != 0; }
const char* user() { return SECRET_IITG_USER; }
const char* lastResult() { return s_result; }
int logins() { return s_logins; }
int keepalives() { return s_keeps; }

void init() {
    if (!haveCredentials())
        logf("PORTAL", "no IITG credentials in .env; campus auto-login is off");
    else
        logf("PORTAL", "campus auto-login for %s (%s)", SECRET_IITG_USER,
             settings::portalAuto() ? "on" : "off");
}

void loginNow() {
    s_force = true;
    s_paused = false;
    s_rejects = 0;
    s_netFails = 0;
    setResult("logging in...");
}

bool logout() {
    s_wantLogout = true;
    setResult("logging out...");
    return true;
}

void loop() {
    if (!haveCredentials() || !network::connected()) return;
    // Never stall or compete for TLS / heap during a sign-in or OTA.
    if (ctap::busy() || hybrid::state() != hybrid::State::Idle || network::otaActive()) return;

    uint32_t now = millis();
    if (s_wantLogout) { s_wantLogout = false; doLogout(); s_next = now + (uint32_t)PORTAL_PROBE_SECS * 1000UL; return; }
    if (s_force) { s_force = false; doLogin(now, true); return; }
    if ((int32_t)(now - s_next) < 0) return;

    bool autoOn = settings::portalAuto() && !s_paused;
    Probe pr = probe();

    if (pr == Probe::Online) {
        s_state = St::Online;
        s_netFails = 0;
        if (s_magic[0] && !s_paused) {
            if ((int32_t)(now - s_nextKeep) >= 0) {
                if (keepalive()) {
                    s_nextKeep = now + (uint32_t)PORTAL_KEEPALIVE_SECS * 1000UL;
                } else if (autoOn) {
                    event("Portal: session ended, logging in");
                    s_next = now + 2000;   // log straight back in
                    return;
                }
            }
        } else if (autoOn && (int32_t)(now - s_nextAdopt) >= 0) {
            // Online through someone else's login (e.g. a browser): take the
            // session over so it can be refreshed before it expires.
            logf("PORTAL", "online but no session of ours; taking it over to keep it alive");
            if (login() == Res::Ok) {
                s_logins++;
                s_nextKeep = now + (uint32_t)PORTAL_KEEPALIVE_SECS * 1000UL;
                setResult("logged in");
                event("Portal: logged in (%s)", SECRET_IITG_USER);
            } else {
                s_nextAdopt = now + (uint32_t)PORTAL_CRED_BACKOFF_SECS * 1000UL;   // don't fight it
                setResult("online (not ours)");
            }
        }
        s_next = now + (uint32_t)PORTAL_PROBE_SECS * 1000UL;
        return;
    }

    // Not logged in (or the probe got no answer).
    if (s_state == St::Online) event("Portal: session lost");
    s_magic[0] = '\0';
    if (!autoOn) {
        s_state = St::Offline;
        setResult(s_paused ? "logged out (paused)" : "offline (auto-login off)");
        s_next = now + (uint32_t)PORTAL_PROBE_SECS * 1000UL;
        return;
    }
    doLogin(now, false);
}

const char* stateStr() {
    if (!haveCredentials()) return "no credentials";
    if (s_paused && s_state != St::Online) return "logged out";
    switch (s_state) {
        case St::Offline:   return "offline";
        case St::LoggingIn: return "logging in";
        case St::Online:    return "online";
        case St::Limit:     return "limit reached";
        case St::Failed:    return "login failed";
    }
    return "?";
}

uint32_t secondsToNext() {
    uint32_t target = (s_state == St::Online && s_magic[0]) ? s_nextKeep : s_next;
    int32_t left = (int32_t)(target - millis());
    return left > 0 ? (uint32_t)left / 1000UL : 0;
}

}  // namespace portal
