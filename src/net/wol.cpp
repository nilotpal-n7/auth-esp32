#include "net/wol.h"
#include "core/log.h"
#include "fido/ctap2.h"
#include "net/network.h"

#include <Preferences.h>
#include <WiFi.h>
#include <lwip/sockets.h>
#include <stddef.h>

namespace wol {

struct Seed { const char* name; const char* mac; const char* ip; const char* ports; const char* bcast; const char* maint; };
#ifdef SECRET_WOL_HOSTS
static const Seed SEEDS[] = { SECRET_WOL_HOSTS };
#else
static const Seed SEEDS[] = { WOL_DEFAULT_HOST };
#endif

// Records saved by 2.0 end where `alerts` begins; they are migrated on load.
static const size_t HOST_V1_SIZE = 62;
static_assert(offsetof(Host, alerts) == HOST_V1_SIZE, "Host v1 layout changed");

#define M_PREWOKE 1
#define M_ACTIVE  2
#define WEEK_MIN  (7 * 1440)

// Per-host runtime state (not stored).
struct Runtime {
    int8_t   state;            // -1 unknown, 0 down, 1 up (last check)
    uint32_t checkedMs;        // 0 = never
    int8_t   packetsLeft;
    uint32_t nextPacketMs;
    bool     watching;
    uint32_t wakeMs, nextWatchMs;
    uint32_t downSinceMs;      // auto-wake: first failed check (0 = not down)
    uint8_t  autoTries;
    char     why[16];
    // Monitor / alerts
    uint8_t  fails;            // failed checks in a row
    int8_t   known;            // state the alerts know about (-1 unknown)
    time_t   since;            // UTC of the last change (0 = unknown)
    time_t   firstFail;
    bool     expectOff;
    char     offWhy[24];
    uint32_t restartUntilMs;   // expectRestart() deadline (0 = none)
    bool     restartDown;      // seen down since the reboot
    // Maintenance windows
    uint8_t  mflags[WOL_MAINT_SLOTS];
    time_t   mStart[WOL_MAINT_SLOTS];
    uint8_t  mDowns;           // times it went down inside the window
    time_t   mDownAt;          // last time it went down inside the window
    uint32_t mDownSecs;        // total downtime inside the window
};

static Preferences s_prefs;
static Host        s_hosts[WOL_MAX_HOSTS];
static Runtime     s_rt[WOL_MAX_HOSTS];
static int         s_count = 0;
static bool        s_enabled = true;
static NotifyFn    s_notify = nullptr;
static NotifyFn    s_alert = nullptr;
static MaintEndFn  s_maintEnd = nullptr;
static int         s_autoNext = 0;          // round-robin index for monitor checks
static uint32_t    s_autoNextMs = 0;
static uint32_t    s_maintNextMs = 0;

static void vsend(NotifyFn fn, const char* fmt, va_list ap) {
    char msg[360];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    logf("WOL", "%s", msg);
    if (fn) fn(msg);
}

static void report(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void report(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsend(s_notify, fmt, ap);
    va_end(ap);
}

static void alert(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void alert(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsend(s_alert, fmt, ap);
    va_end(ap);
}

static void resetRuntime(int i) {
    memset(&s_rt[i], 0, sizeof(Runtime));
    s_rt[i].state = -1;
    s_rt[i].known = -1;
}

// --- Text helpers -----------------------------------------------------------------------

static void fmtDur(uint32_t s, char* out, size_t cap) {
    if (s < 90) snprintf(out, cap, "%lu s", (unsigned long)s);
    else if (s < 5400) snprintf(out, cap, "%lu min", (unsigned long)((s + 30) / 60));
    else if (s < 2 * 86400) snprintf(out, cap, "%lu h %lu min", (unsigned long)(s / 3600), (unsigned long)(s % 3600 / 60));
    else snprintf(out, cap, "%lu d %lu h", (unsigned long)(s / 86400), (unsigned long)(s % 86400 / 3600));
}

static void fmtClock(time_t t, char* out, size_t cap) {
    if (!t) { strlcpy(out, "?", cap); return; }
    struct tm lt;
    localtime_r(&t, &lt);
    strftime(out, cap, "%a %H:%M", &lt);
}

static const char* const DAYS[7] = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"};

uint32_t parseDuration(const char* s) {
    if (!s || !*s) return 0;
    char* end;
    double v = strtod(s, &end);
    if (end == s || v <= 0) return 0;
    switch (tolower(*end)) {
        case 'd': v *= 86400; break;
        case 'h': v *= 3600; break;
        case 's': break;
        default:  v *= 60; break;      // "30", "30m", "30min"
    }
    return v > 30 * 86400 ? 30 * 86400 : (uint32_t)v;
}

bool parseWindow(const char* text, Window* w, char* err, size_t errCap) {
    memset(w, 0, sizeof(*w));
    char buf[48];
    strlcpy(buf, text ? text : "", sizeof(buf));
    char* save;
    char* days = strtok_r(buf, " ", &save);
    char* at = strtok_r(nullptr, " ", &save);
    char* len = strtok_r(nullptr, " ", &save);
    if (!days || !at || !len) { snprintf(err, errCap, "like: sat 00:00 120  (days, start, minutes)"); return false; }
    if (!strcasecmp(days, "daily") || !strcasecmp(days, "every")) w->days = 0x7F;
    else if (!strcasecmp(days, "weekdays")) w->days = 0x3E;
    else if (!strcasecmp(days, "weekend")) w->days = 0x41;
    else {
        for (char* d = strtok_r(days, ",", &save); d; d = strtok_r(nullptr, ",", &save)) {
            int a = -1, b = -1;
            char* dash = strchr(d, '-');
            if (dash) *dash = '\0';
            for (int k = 0; k < 7; k++) {
                if (!strncasecmp(d, DAYS[k], 3)) a = k;
                if (dash && !strncasecmp(dash + 1, DAYS[k], 3)) b = k;
            }
            if (a < 0 || (dash && b < 0)) { snprintf(err, errCap, "days: sun..sat, mon-fri, daily, weekend"); return false; }
            if (b < 0) b = a;
            for (int k = a;; k = (k + 1) % 7) { w->days |= 1 << k; if (k == b) break; }
        }
    }
    int hh = -1, mm = -1;
    if (sscanf(at, "%d:%d", &hh, &mm) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59) {
        snprintf(err, errCap, "start like 00:00 (24 h, local time)");
        return false;
    }
    uint32_t mins = parseDuration(len) / 60;
    if (mins < 1 || mins > 1440) { snprintf(err, errCap, "length: 1-1440 minutes (or 2h)"); return false; }
    w->hour = hh;
    w->minute = mm;
    w->minutes = mins;
    return true;
}

void formatWindow(const Window& w, char* out, size_t cap) {
    char d[32] = "";
    if (w.days == 0x7F) strlcpy(d, "daily", sizeof(d));
    else {
        for (int k = 0; k < 7; k++) {
            if (!(w.days & (1 << k))) continue;
            if (d[0]) strlcat(d, ",", sizeof(d));
            char n[4] = {(char)toupper(DAYS[k][0]), DAYS[k][1], DAYS[k][2], 0};
            strlcat(d, n, sizeof(d));
        }
    }
    snprintf(out, cap, "%s %02u:%02u, %u min", d, w.hour, w.minute, w.minutes);
}

// --- Parsing --------------------------------------------------------------------------

bool parseMac(const char* s, uint8_t mac[6]) {
    int n = 0;
    while (*s && n < 12) {
        char c = *s++;
        if (c == ':' || c == '-' || c == '.') continue;
        int v = isdigit((unsigned char)c) ? c - '0' : (tolower(c) >= 'a' && tolower(c) <= 'f') ? tolower(c) - 'a' + 10 : -1;
        if (v < 0) return false;
        if (n % 2 == 0) mac[n / 2] = v << 4; else mac[n / 2] |= v;
        n++;
    }
    return n == 12 && !*s;
}

void formatMac(const uint8_t m[6], char* out, size_t cap) {
    snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

bool makeHost(const char* name, const char* mac, const char* ip, const char* ports, const char* bcast,
              Host* h, char* err, size_t errCap) {
    memset(h, 0, sizeof(*h));
    if (!name || !*name || strlen(name) >= sizeof(h->name)) { snprintf(err, errCap, "name: 1-15 characters"); return false; }
    for (const char* p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_') { snprintf(err, errCap, "name: letters, digits, - or _"); return false; }
    }
    if (isdigit((unsigned char)name[0])) { snprintf(err, errCap, "name must not start with a digit"); return false; }
    strlcpy(h->name, name, sizeof(h->name));
    if (!mac || !parseMac(mac, h->mac)) { snprintf(err, errCap, "MAC like 64:00:6a:2b:36:9f"); return false; }
    IPAddress a;
    if (ip && *ip && strcmp(ip, "-")) {
        if (!a.fromString(ip)) { snprintf(err, errCap, "IP like 172.16.114.175 (or - for none)"); return false; }
        strlcpy(h->ip, a.toString().c_str(), sizeof(h->ip));
    }
    int n = 0;
    for (const char* p = ports && *ports ? ports : "8006,22"; *p && n < 2;) {
        long v = strtol(p, (char**)&p, 10);
        if (v <= 0 || v > 65535) { snprintf(err, errCap, "ports like 8006,22"); return false; }
        h->ports[n++] = (uint16_t)v;
        while (*p == ',' || *p == ' ') p++;
    }
    if (bcast && *bcast && strcmp(bcast, "-")) {
        if (!a.fromString(bcast)) { snprintf(err, errCap, "broadcast like 172.16.119.255"); return false; }
        strlcpy(h->broadcast, a.toString().c_str(), sizeof(h->broadcast));
    }
    h->autoMin = WOL_AUTO_DEFAULT_MIN;
    h->alerts = true;
    h->maintWake = true;
    return true;
}

void copySettings(const Host& from, Host* to) {
    to->autoWake = from.autoWake;
    to->autoMin = from.autoMin;
    to->alerts = from.alerts;
    to->maintWake = from.maintWake;
    to->pausedUntil = from.pausedUntil;
    memcpy(to->maint, from.maint, sizeof(to->maint));
}

// --- Storage ---------------------------------------------------------------------------

static void persist() {
    s_prefs.putInt("n", s_count);
    for (int i = 0; i < WOL_MAX_HOSTS; i++) {
        char key[8];
        snprintf(key, sizeof(key), "h%d", i);
        if (i < s_count) s_prefs.putBytes(key, &s_hosts[i], sizeof(Host));
        else if (s_prefs.isKey(key)) s_prefs.remove(key);
    }
}

static void seedWindows(Host* h, const char* spec) {
    // "sat 00:00 120; sun 00:00 120"
    char buf[80], err[48];
    strlcpy(buf, spec ? spec : "", sizeof(buf));
    int slot = 0;
    char* save;
    for (char* part = strtok_r(buf, ";", &save); part && slot < WOL_MAINT_SLOTS; part = strtok_r(nullptr, ";", &save)) {
        while (*part == ' ') part++;
        if (!*part) continue;
        if (parseWindow(part, &h->maint[slot], err, sizeof(err))) slot++;
        else logf("WOL", "%s: maintenance \"%s\" ignored: %s", h->name, part, err);
    }
}

void resetToDefaults() {
    s_count = 0;
    char err[48];
    for (const Seed& sd : SEEDS) {
        if (s_count >= WOL_MAX_HOSTS) break;
        if (makeHost(sd.name, sd.mac, sd.ip, sd.ports, sd.bcast, &s_hosts[s_count], err, sizeof(err))) {
            seedWindows(&s_hosts[s_count], sd.maint);
            s_count++;
        } else {
            logf("WOL", "default host %s ignored: %s", sd.name, err);
        }
    }
    for (int i = 0; i < WOL_MAX_HOSTS; i++) resetRuntime(i);
    persist();
    logf("WOL", "%d host(s) from defaults", s_count);
}

void init() {
    s_prefs.begin("wol", false);
    s_enabled = s_prefs.getBool("on", true);
    s_count = s_prefs.getInt("n", -1);
    if (s_count < 0) {
        resetToDefaults();
        // Settings from the single-server version carry over to the first host.
        if (s_count > 0) {
            if (s_prefs.isKey("ip")) s_prefs.getString("ip", s_hosts[0].ip, sizeof(s_hosts[0].ip));
            s_hosts[0].autoWake = s_prefs.getBool("auto", false);
            s_hosts[0].autoMin = s_prefs.getInt("autoMin", WOL_AUTO_DEFAULT_MIN);
            for (const char* k : {"ip", "auto", "autoMin"}) if (s_prefs.isKey(k)) s_prefs.remove(k);
            persist();
        }
    } else {
        if (s_count > WOL_MAX_HOSTS) s_count = WOL_MAX_HOSTS;
        bool migrated = false;
        for (int i = 0; i < s_count; i++) {
            char key[8];
            snprintf(key, sizeof(key), "h%d", i);
            size_t len = s_prefs.getBytesLength(key);
            memset(&s_hosts[i], 0, sizeof(Host));
            if (len == sizeof(Host)) {
                s_prefs.getBytes(key, &s_hosts[i], sizeof(Host));
            } else if (len == HOST_V1_SIZE) {
                s_prefs.getBytes(key, &s_hosts[i], HOST_V1_SIZE);
                s_hosts[i].alerts = true;
                s_hosts[i].maintWake = true;
                migrated = true;
            } else {
                s_count = i;
                break;
            }
            s_hosts[i].name[sizeof(s_hosts[i].name) - 1] = '\0';
        }
        if (migrated) { persist(); logf("WOL", "machines migrated to the 2.1 format (alerts on)"); }
    }
    for (int i = 0; i < WOL_MAX_HOSTS; i++) resetRuntime(i);
    logf("WOL", "%d host(s), wake-on-LAN %s", s_count, s_enabled ? "on" : "off");
}

void setNotifier(NotifyFn fn) { s_notify = fn; }
void setAlertNotifier(NotifyFn fn) { s_alert = fn; }
void setMaintEndHandler(MaintEndFn fn) { s_maintEnd = fn; }

int count() { return s_count; }
const Host* host(int i) { return i >= 0 && i < s_count ? &s_hosts[i] : nullptr; }

int find(const char* s) {
    if (!s || !*s) return -1;
    if (isdigit((unsigned char)s[0])) {
        int n = atoi(s);
        return n >= 1 && n <= s_count ? n - 1 : -1;
    }
    for (int i = 0; i < s_count; i++) if (!strcasecmp(s_hosts[i].name, s)) return i;
    return -1;
}

int put(const Host& h, char* err, size_t errCap) {
    int i = find(h.name);
    if (i < 0) {
        if (s_count >= WOL_MAX_HOSTS) { snprintf(err, errCap, "already %d machines", WOL_MAX_HOSTS); return -1; }
        i = s_count++;
        resetRuntime(i);
    } else {
        s_rt[i].state = -1;   // address may have changed
        s_rt[i].known = -1;
        s_rt[i].fails = 0;
    }
    s_hosts[i] = h;
    persist();
    return i;
}

bool remove(int i) {
    if (i < 0 || i >= s_count) return false;
    for (int j = i; j < s_count - 1; j++) { s_hosts[j] = s_hosts[j + 1]; s_rt[j] = s_rt[j + 1]; }
    s_count--;
    resetRuntime(s_count);
    persist();
    return true;
}

bool enabled() { return s_enabled; }
void setEnabled(bool on) {
    s_enabled = on;
    s_prefs.putBool("on", on);
    if (!on) for (int i = 0; i < s_count; i++) { s_rt[i].packetsLeft = 0; s_rt[i].watching = false; }
}

void setAutoWake(int i, bool on, int minutes) {
    if (i < 0 || i >= s_count) return;
    s_hosts[i].autoWake = on;
    if (minutes > 0) s_hosts[i].autoMin = minutes > 1440 ? 1440 : minutes;
    s_rt[i].downSinceMs = 0;
    s_rt[i].autoTries = 0;
    persist();
}

void setAlerts(int i, bool on) {
    if (i < 0 || i >= s_count) return;
    s_hosts[i].alerts = on;
    persist();
}

int  lastState(int i) { return i >= 0 && i < s_count ? s_rt[i].state : -1; }
bool waking(int i) { return i >= 0 && i < s_count && (s_rt[i].packetsLeft > 0 || s_rt[i].watching); }
uint32_t lastCheckAgeS(int i) {
    if (i < 0 || i >= s_count || !s_rt[i].checkedMs) return UINT32_MAX;
    return (millis() - s_rt[i].checkedMs) / 1000;
}
time_t stateSince(int i) { return i >= 0 && i < s_count ? s_rt[i].since : 0; }

// --- Pause ------------------------------------------------------------------------------------

bool paused(int i) {
    if (i < 0 || i >= s_count) return false;
    uint32_t p = s_hosts[i].pausedUntil;
    if (!p) return false;
    if (p == WOL_PAUSE_UNTIL_UP) return true;
    time_t now = network::now();
    return !now || now < (time_t)p;    // clock unknown: stay paused until it is set
}

bool pause(int i, uint32_t seconds) {
    if (i < 0 || i >= s_count) return false;
    if (seconds && seconds != WOL_PAUSE_UNTIL_UP) {
        time_t now = network::now();
        if (!now) return false;        // needs the clock
        s_hosts[i].pausedUntil = (uint32_t)(now + seconds);
    } else {
        s_hosts[i].pausedUntil = seconds;
    }
    s_rt[i].downSinceMs = 0;
    s_rt[i].autoTries = 0;
    if (!seconds) s_rt[i].expectOff = false;
    persist();
    return true;
}

void expectRestart(int i) {
    if (i < 0 || i >= s_count) return;
    s_rt[i].restartUntilMs = (millis() + WOL_RESTART_WAIT_MIN * 60000UL) | 1;
    s_rt[i].restartDown = false;
    s_rt[i].downSinceMs = 0;
}

void expectShutdown(int i, const char* why) {
    if (i < 0 || i >= s_count) return;
    pause(i, WOL_PAUSE_UNTIL_UP);
    s_rt[i].expectOff = true;
    s_rt[i].watching = false;
    s_rt[i].packetsLeft = 0;
    strlcpy(s_rt[i].offWhy, why, sizeof(s_rt[i].offWhy));
}

// --- Maintenance windows -------------------------------------------------------------------

bool addWindow(int i, const Window& w, char* err, size_t errCap) {
    if (i < 0 || i >= s_count) { snprintf(err, errCap, "no such machine"); return false; }
    for (Window& slot : s_hosts[i].maint) {
        if (slot.days) continue;
        slot = w;
        persist();
        return true;
    }
    snprintf(err, errCap, "already %d windows: clear them first", WOL_MAINT_SLOTS);
    return false;
}

void clearWindows(int i) {
    if (i < 0 || i >= s_count) return;
    memset(s_hosts[i].maint, 0, sizeof(s_hosts[i].maint));
    memset(s_rt[i].mflags, 0, sizeof(s_rt[i].mflags));
    persist();
}

void setMaintWake(int i, bool on) {
    if (i < 0 || i >= s_count) return;
    s_hosts[i].maintWake = on;
    persist();
}

bool inMaintenance(int i) {
    if (i < 0 || i >= s_count) return false;
    for (uint8_t f : s_rt[i].mflags) if (f & M_ACTIVE) return true;
    return false;
}

// Minutes since the window started (if inside it) and until its next start.
static void windowPos(const Window& w, const struct tm& lt, int* since, int* until) {
    int wk = lt.tm_wday * 1440 + lt.tm_hour * 60 + lt.tm_min;
    *since = -1;
    *until = WEEK_MIN;
    for (int d = 0; d < 7; d++) {
        if (!(w.days & (1 << d))) continue;
        int start = d * 1440 + w.hour * 60 + w.minute;
        int diff = (wk - start + WEEK_MIN) % WEEK_MIN;
        if (diff < w.minutes && (*since < 0 || diff < *since)) *since = diff;
        int u = (start - wk + WEEK_MIN) % WEEK_MIN;
        if (u > 0 && u < *until) *until = u;
    }
}

time_t nextWindow(int i) {
    time_t now = network::now();
    if (i < 0 || i >= s_count || !now) return 0;
    struct tm lt;
    localtime_r(&now, &lt);
    int best = WEEK_MIN;
    for (const Window& w : s_hosts[i].maint) {
        if (!w.days) continue;
        int since, until;
        windowPos(w, lt, &since, &until);
        if (until < best) best = until;
    }
    return best < WEEK_MIN ? now - lt.tm_sec + best * 60 : 0;
}

// --- Magic packet ------------------------------------------------------------------------

static bool sendTo(int sock, const uint8_t* pkt, size_t len, IPAddress dst) {
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(WOL_UDP_PORT);
    a.sin_addr.s_addr = (uint32_t)dst;
    return sendto(sock, pkt, len, 0, (sockaddr*)&a, sizeof(a)) == (int)len;
}

// One round to every broadcast address we know. Raw socket because Arduino's
// WiFiUDP never sets SO_BROADCAST.
static int sendRound(const Host& h) {
    uint8_t pkt[6 + 16 * 6];
    memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, h.mac, 6);
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return 0;
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    uint32_t targets[3];
    int n = 0;
    targets[n++] = 0xFFFFFFFFu;
    IPAddress b;
    if (h.broadcast[0] && b.fromString(h.broadcast)) targets[n++] = (uint32_t)b;
    uint32_t sub = (uint32_t)WiFi.broadcastIP();
    bool dup = !sub || sub == 0xFFFFFFFFu;
    for (int i = 0; i < n; i++) dup |= targets[i] == sub;
    if (!dup) targets[n++] = sub;

    int sent = 0;
    for (int i = 0; i < n; i++) sent += sendTo(sock, pkt, sizeof(pkt), IPAddress(targets[i]));
    close(sock);
    return sent;
}

bool wake(int i, const char* why) {
    if (!s_enabled || i < 0 || i >= s_count) return false;
    strlcpy(s_rt[i].why, why, sizeof(s_rt[i].why));
    s_rt[i].packetsLeft = WOL_PACKETS;
    s_rt[i].nextPacketMs = millis();
    s_rt[i].watching = false;
    s_rt[i].expectOff = false;
    return true;
}

// --- Reachability ---------------------------------------------------------------------------

// Every check result goes through here: tracks up / down changes and alerts.
static void observe(int i, bool up) {
    Host& h = s_hosts[i];
    Runtime& r = s_rt[i];
    time_t now = network::now();
    char d[24], t[16];
    if (up) {
        r.fails = 0;
        if (r.known == 0) {
            uint32_t down = r.since && now ? now - r.since : 0;
            fmtDur(down, d, sizeof(d));
            logEvent("Server %s up", h.name);
            if (r.restartUntilMs) {
                r.restartUntilMs = 0;
                report("🟢 %s is back after the reboot (down %s).", h.name, d);
            } else if (inMaintenance(i)) {
                if (r.mDownAt && now) r.mDownSecs += now - r.mDownAt;
                r.mDownAt = 0;
            } else if (!r.watching && h.alerts && !paused(i)) {
                if (down) alert("🟢 %s is back up (it was down %s).", h.name, d);
                else alert("🟢 %s is back up.", h.name);
            }
        }
        if (r.known != 1) { r.known = 1; r.since = now; }
        if (h.pausedUntil == WOL_PAUSE_UNTIL_UP) {
            h.pausedUntil = 0;
            persist();
            logf("WOL", "%s is up: auto-wake / alerts resume", h.name);
        }
        r.expectOff = false;
        return;
    }
    if (r.fails < 255) r.fails++;
    if (r.fails == 1) r.firstFail = now;
    if (r.known == 0 || (r.known == 1 && r.fails < 2)) return;   // one miss isn't "down" yet
    bool wasUp = r.known == 1;
    r.known = 0;
    r.since = r.firstFail ? r.firstFail : now;
    if (!wasUp) return;                 // first state after boot: no alert
    logEvent("Server %s down", h.name);
    fmtClock(r.since, t, sizeof(t));
    if (r.restartUntilMs) {
        r.restartDown = true;
        logf("WOL", "%s is down for its reboot", h.name);
    } else if (r.expectOff) {
        r.expectOff = false;
        report("⏻ %s is off (%s). Auto-wake and alerts stay paused until it is up again (/wake %s).",
               h.name, r.offWhy, h.name);
    } else if (inMaintenance(i)) {
        r.mDowns++;
        r.mDownAt = r.since;
        logf("WOL", "%s went down inside its maintenance window", h.name);
    } else if (h.alerts && !paused(i)) {
        alert("🔴 %s went down (no answer since %s).%s", h.name, t,
              h.autoWake ? " Auto-wake will try in a few minutes." : "");
    }
}

bool check(int i, uint16_t* port, uint32_t* ms) {
    if (port) *port = 0;
    if (i < 0 || i >= s_count || !network::connected()) return false;
    IPAddress ip;
    if (!s_hosts[i].ip[0] || !ip.fromString(s_hosts[i].ip)) return false;
    bool up = false;
    for (uint16_t p : s_hosts[i].ports) {
        if (!p) continue;
        WiFiClient c;
        uint32_t t0 = millis();
        if (c.connect(ip, p, WOL_CONNECT_TIMEOUT_MS)) {
            c.stop();
            if (port) *port = p;
            if (ms) *ms = millis() - t0;
            up = true;
            break;
        }
    }
    s_rt[i].state = up ? 1 : 0;
    s_rt[i].checkedMs = millis() | 1;
    observe(i, up);
    return up;
}

// --- Loop -------------------------------------------------------------------------------------

// Sends due packets and runs the post-wake watch for host i. True if it did
// something (one blocking step per loop pass at most).
static bool serviceHost(int i, uint32_t now) {
    Host& h = s_hosts[i];
    Runtime& r = s_rt[i];
    if (r.packetsLeft > 0 && (int32_t)(now - r.nextPacketMs) >= 0) {
        if (!network::connected()) {
            r.packetsLeft = 0;
            report("❌ Can't wake %s: the AuthKey has no WiFi.", h.name);
            return true;
        }
        int sent = sendRound(h);
        r.packetsLeft--;
        r.nextPacketMs = now + 1000;
        logf("WOL", "%s: magic packet round (%d address(es)), %d left", h.name, sent, r.packetsLeft);
        if (r.packetsLeft == 0) {
            char mac[18];
            formatMac(h.mac, mac, sizeof(mac));
            logEvent("WoL %s (%s)", h.name, r.why);
            if (h.ip[0]) {
                report("⏰ Magic packet sent %d× to %s (%s). Watching for %d min…", WOL_PACKETS, h.name, mac,
                       WOL_WATCH_SECS / 60);
                r.watching = true;
                r.wakeMs = now;
                r.nextWatchMs = now + WOL_WATCH_EVERY_SECS * 1000UL;
            } else {
                report("⏰ Magic packet sent %d× to %s (%s). No IP set, so I can't tell when it's up.",
                       WOL_PACKETS, h.name, mac);
            }
        }
        return true;
    }
    if (r.watching && (int32_t)(now - r.nextWatchMs) >= 0 && !ctap::busy()) {
        uint16_t port;
        if (check(i, &port)) {
            r.watching = false;
            r.downSinceMs = 0;
            r.autoTries = 0;
            logEvent("%s up after WoL", h.name);
            report("🟢 %s is up (%lu s after the wake, port %u answered).", h.name,
                   (unsigned long)((millis() - r.wakeMs) / 1000), port);
        } else if (now - r.wakeMs >= WOL_WATCH_SECS * 1000UL) {
            r.watching = false;
            logEvent("%s still down after WoL", h.name);
            report("🔴 %s didn't come up within %d min. Check its BIOS (wake-on-LAN on, deep sleep off) "
                   "and that it still has power.", h.name, WOL_WATCH_SECS / 60);
        } else {
            r.nextWatchMs = now + WOL_WATCH_EVERY_SECS * 1000UL;
        }
        return true;
    }
    return false;
}

static void endWindow(int i, int slot) {
    Host& h = s_hosts[i];
    Runtime& r = s_rt[i];
    time_t now = network::now();
    bool up = h.ip[0] ? check(i) : false;
    char win[40], text[300], d[24], t[16];
    formatWindow(h.maint[slot], win, sizeof(win));
    if (r.mDownAt && now) { r.mDownSecs += now - r.mDownAt; r.mDownAt = up ? 0 : r.mDownAt; }
    int n = snprintf(text, sizeof(text), "🛠 %s: maintenance window (%s) is over.\n", h.name, win);
    if (!h.ip[0]) {
        snprintf(text + n, sizeof(text) - n, "No IP set, so I can't tell whether it is up.");
    } else if (up) {
        if (r.mDowns) {
            fmtDur(r.mDownSecs, d, sizeof(d));
            snprintf(text + n, sizeof(text) - n, "🟢 Up. It restarted %u× inside the window (down %s in total).",
                     r.mDowns, d);
        } else {
            snprintf(text + n, sizeof(text) - n, "🟢 Up, and it stayed up the whole time.");
        }
    } else {
        fmtClock(r.since, t, sizeof(t));
        if (h.autoWake && !paused(i))
            snprintf(text + n, sizeof(text) - n, "🔴 Still down (since %s). Auto-wake tries in %u min.", t, h.autoMin);
        else
            snprintf(text + n, sizeof(text) - n, "🔴 Still down (since %s). /wake %s", t, h.name);
    }
    logEvent("%s maintenance over (%s)", h.name, up ? "up" : "down");
    r.downSinceMs = 0;            // auto-wake counts from the end of the window
    time_t start = r.mStart[slot];
    r.mDowns = 0;
    r.mDownSecs = 0;
    if (!(s_maintEnd && s_maintEnd(i, text, start))) alert("%s", text);
}

// Window starts / ends and the wake shortly before. Runs every few seconds.
static void serviceWindows() {
    time_t now = network::now();
    if (!now) return;
    struct tm lt;
    localtime_r(&now, &lt);
    for (int i = 0; i < s_count; i++) {
        Host& h = s_hosts[i];
        Runtime& r = s_rt[i];
        for (int s = 0; s < WOL_MAINT_SLOTS; s++) {
            const Window& w = h.maint[s];
            uint8_t& f = r.mflags[s];
            if (!w.days) { f = 0; continue; }
            int since, until;
            windowPos(w, lt, &since, &until);
            bool active = since >= 0;
            if (!active && until <= WOL_MAINT_PREWAKE_MIN && !(f & M_PREWOKE)) {
                f |= M_PREWOKE;
                char win[40];
                formatWindow(w, win, sizeof(win));
                if (!h.maintWake || !s_enabled || paused(i)) {
                    logf("WOL", "%s: window %s soon; not waking (%s)", h.name, win,
                         !h.maintWake ? "wake before windows off" : !s_enabled ? "WoL off" : "paused");
                } else if (h.ip[0] && check(i)) {
                    logf("WOL", "%s: window %s soon, already up", h.name, win);
                } else {
                    alert("🛠 %s is off and its maintenance window (%s) starts in %d min: waking it.", h.name, win, until);
                    wake(i, "maintenance");
                }
                return;                    // one blocking step per pass
            }
            if (active && !(f & M_ACTIVE)) {
                f |= M_ACTIVE;
                r.mStart[s] = now - lt.tm_sec - since * 60;
                r.mDowns = 0;
                r.mDownSecs = 0;
                r.mDownAt = 0;
                r.downSinceMs = 0;
                logEvent("%s maintenance start", h.name);
            } else if (!active && (f & M_ACTIVE)) {
                f &= ~M_ACTIVE;
                endWindow(i, s);
                return;
            }
            if (!active && until > WOL_MAINT_PREWAKE_MIN) f &= ~M_PREWOKE;
        }
    }
}

void loop() {
    if (!s_count) return;
    uint32_t now = millis();

    // Timed pauses that ran out.
    time_t utc = network::now();
    for (int i = 0; i < s_count; i++) {
        uint32_t p = s_hosts[i].pausedUntil;
        if (p && p != WOL_PAUSE_UNTIL_UP && utc && utc >= (time_t)p) {
            s_hosts[i].pausedUntil = 0;
            persist();
            report("▶️ %s: the pause is over; auto-wake and alerts are back on.", s_hosts[i].name);
        }
    }

    // Reboots that took too long (or were too quick to be seen).
    for (int i = 0; i < s_count; i++) {
        Runtime& r = s_rt[i];
        if (!r.restartUntilMs || (int32_t)(now - r.restartUntilMs) < 0) continue;
        r.restartUntilMs = 0;
        if (r.known == 0) alert("🔴 %s didn't come back within %d min of the reboot.", s_hosts[i].name, WOL_RESTART_WAIT_MIN);
    }

    if (s_enabled) for (int i = 0; i < s_count; i++) if (serviceHost(i, now)) return;

    if ((int32_t)(now - s_maintNextMs) >= 0) {
        s_maintNextMs = now + 5000;
        if (!ctap::busy() && network::connected()) serviceWindows();
    }

    // Monitor: one host per step, each about every WOL_AUTO_CHECK_SECS.
    if (ctap::busy() || !network::connected() || (int32_t)(now - s_autoNextMs) < 0) return;
    uint32_t step = WOL_AUTO_CHECK_SECS * 1000UL / (s_count ? s_count : 1);
    s_autoNextMs = now + (step < 5000 ? 5000 : step);
    int i = s_autoNext++ % s_count;
    Host& h = s_hosts[i];
    Runtime& r = s_rt[i];
    if (!h.ip[0] || r.watching || r.packetsLeft) return;
    bool windows = h.maint[0].days || h.maint[1].days;
    if (!h.alerts && !h.autoWake && !windows && !r.expectOff && !r.restartUntilMs) return;
    if (check(i)) {
        if (r.downSinceMs) logf("WOL", "%s reachable again", h.name);
        r.downSinceMs = 0;
        r.autoTries = 0;
        return;
    }
    // Auto-wake (not while paused or inside a maintenance window).
    if (!s_enabled || !h.autoWake || paused(i) || inMaintenance(i) || r.restartUntilMs) { r.downSinceMs = 0; return; }
    if (!r.downSinceMs) { r.downSinceMs = now; return; }
    if (now - r.downSinceMs < (uint32_t)h.autoMin * 60000UL || r.autoTries >= WOL_AUTO_MAX_TRIES) return;
    r.autoTries++;
    r.downSinceMs = now;   // a further try (if needed) waits another N minutes
    report("⚠️ %s has been unreachable for %d min: sending a magic packet (auto-wake, try %d of %d).",
           h.name, h.autoMin, r.autoTries, WOL_AUTO_MAX_TRIES);
    wake(i, "auto-wake");
}

}  // namespace wol
