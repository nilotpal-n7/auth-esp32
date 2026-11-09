#include "net/wol.h"
#include "core/log.h"
#include "fido/ctap2.h"
#include "net/network.h"

#include <Preferences.h>
#include <WiFi.h>
#include <lwip/sockets.h>

namespace wol {

struct Seed { const char* name; const char* mac; const char* ip; const char* ports; const char* bcast; };
#ifdef SECRET_WOL_HOSTS
static const Seed SEEDS[] = { SECRET_WOL_HOSTS };
#else
static const Seed SEEDS[] = { WOL_DEFAULT_HOST };
#endif

// Per-host runtime state (not stored).
struct Runtime {
    int8_t   state;            // -1 unknown, 0 down, 1 up
    uint32_t checkedMs;        // 0 = never
    int8_t   packetsLeft;
    uint32_t nextPacketMs;
    bool     watching;
    uint32_t wakeMs, nextWatchMs;
    uint32_t downSinceMs;      // auto-wake: first failed check (0 = not down)
    uint8_t  autoTries;
    char     why[16];
};

static Preferences s_prefs;
static Host        s_hosts[WOL_MAX_HOSTS];
static Runtime     s_rt[WOL_MAX_HOSTS];
static int         s_count = 0;
static bool        s_enabled = true;
static NotifyFn    s_notify = nullptr;
static int         s_autoNext = 0;          // round-robin index for auto-wake checks
static uint32_t    s_autoNextMs = 0;

static void report(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void report(const char* fmt, ...) {
    char msg[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    logf("WOL", "%s", msg);
    if (s_notify) s_notify(msg);
}

static void resetRuntime(int i) {
    memset(&s_rt[i], 0, sizeof(Runtime));
    s_rt[i].state = -1;
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
    return true;
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

void resetToDefaults() {
    s_count = 0;
    char err[48];
    for (const Seed& sd : SEEDS) {
        if (s_count >= WOL_MAX_HOSTS) break;
        if (makeHost(sd.name, sd.mac, sd.ip, sd.ports, sd.bcast, &s_hosts[s_count], err, sizeof(err))) s_count++;
        else logf("WOL", "default host %s ignored: %s", sd.name, err);
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
        for (int i = 0; i < s_count; i++) {
            char key[8];
            snprintf(key, sizeof(key), "h%d", i);
            if (s_prefs.getBytes(key, &s_hosts[i], sizeof(Host)) != sizeof(Host)) { s_count = i; break; }
            s_hosts[i].name[sizeof(s_hosts[i].name) - 1] = '\0';
        }
    }
    for (int i = 0; i < WOL_MAX_HOSTS; i++) resetRuntime(i);
    logf("WOL", "%d host(s), wake-on-LAN %s", s_count, s_enabled ? "on" : "off");
}

void setNotifier(NotifyFn fn) { s_notify = fn; }

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

int  lastState(int i) { return i >= 0 && i < s_count ? s_rt[i].state : -1; }
bool waking(int i) { return i >= 0 && i < s_count && (s_rt[i].packetsLeft > 0 || s_rt[i].watching); }
uint32_t lastCheckAgeS(int i) {
    if (i < 0 || i >= s_count || !s_rt[i].checkedMs) return UINT32_MAX;
    return (millis() - s_rt[i].checkedMs) / 1000;
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
    return true;
}

// --- Reachability ---------------------------------------------------------------------------

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

void loop() {
    if (!s_enabled || !s_count) return;
    uint32_t now = millis();
    for (int i = 0; i < s_count; i++) if (serviceHost(i, now)) return;

    // Auto-wake: look at one host per step, each about every WOL_AUTO_CHECK_SECS.
    if (ctap::busy() || !network::connected() || (int32_t)(now - s_autoNextMs) < 0) return;
    uint32_t step = WOL_AUTO_CHECK_SECS * 1000UL / (s_count ? s_count : 1);
    s_autoNextMs = now + (step < 5000 ? 5000 : step);
    int i = s_autoNext++ % s_count;
    Host& h = s_hosts[i];
    Runtime& r = s_rt[i];
    if (!h.autoWake || !h.ip[0] || r.watching || r.packetsLeft) return;
    if (check(i)) {
        if (r.downSinceMs) logf("WOL", "%s reachable again", h.name);
        r.downSinceMs = 0;
        r.autoTries = 0;
        return;
    }
    if (!r.downSinceMs) { r.downSinceMs = now; return; }
    if (now - r.downSinceMs < (uint32_t)h.autoMin * 60000UL || r.autoTries >= WOL_AUTO_MAX_TRIES) return;
    r.autoTries++;
    r.downSinceMs = now;   // a further try (if needed) waits another N minutes
    report("⚠️ %s has been unreachable for %d min: sending a magic packet (auto-wake, try %d of %d).",
           h.name, h.autoMin, r.autoTries, WOL_AUTO_MAX_TRIES);
    wake(i, "auto-wake");
}

}  // namespace wol
