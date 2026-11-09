#include "net/wol.h"
#include "config.h"
#include "core/log.h"
#include "fido/ctap2.h"
#include "net/network.h"

#include <Preferences.h>
#include <WiFi.h>
#include <lwip/sockets.h>

namespace wol {

static const uint8_t MAC[6] = WOL_SERVER_MAC;

static Preferences s_prefs;
static char     s_ip[16] = WOL_DEFAULT_IP;
static bool     s_auto = false;
static int      s_autoMin = WOL_AUTO_DEFAULT_MIN;
static NotifyFn s_notify = nullptr;
static int      s_last = -1;

// Wake in progress: packets still to send, then the watch window.
static int      s_packetsLeft = 0;
static uint32_t s_nextPacketMs = 0;
static bool     s_watching = false;
static uint32_t s_wakeMs = 0, s_nextWatchMs = 0;
static char     s_why[24] = "";

// Auto-wake bookkeeping
static uint32_t s_nextAutoMs = 0;
static uint32_t s_downSinceMs = 0;     // 0 = not seen down
static int      s_autoTries = 0;

static void report(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void report(const char* fmt, ...) {
    char msg[300];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    logf("WOL", "%s", msg);
    if (s_notify) s_notify(msg);
}

void init() {
    s_prefs.begin("wol", false);
    if (s_prefs.isKey("ip")) s_prefs.getString("ip", s_ip, sizeof(s_ip));
    s_auto = s_prefs.getBool("auto", false);
    s_autoMin = s_prefs.getInt("autoMin", WOL_AUTO_DEFAULT_MIN);
    logf("WOL", "server %s at %s, auto-wake %s (%d min)", WOL_SERVER_NAME, s_ip, s_auto ? "on" : "off", s_autoMin);
}

void setNotifier(NotifyFn fn) { s_notify = fn; }

const char* serverIp() { return s_ip; }

bool setServerIp(const char* ip) {
    IPAddress a;
    if (!a.fromString(ip)) return false;
    strlcpy(s_ip, a.toString().c_str(), sizeof(s_ip));
    s_prefs.putString("ip", s_ip);
    s_last = -1;
    return true;
}

bool autoWake() { return s_auto; }
int  autoWakeMinutes() { return s_autoMin; }

void setAutoWake(bool on, int minutes) {
    s_auto = on;
    if (minutes > 0) s_autoMin = minutes > 1440 ? 1440 : minutes;
    s_prefs.putBool("auto", s_auto);
    s_prefs.putInt("autoMin", s_autoMin);
    s_downSinceMs = 0;
    s_autoTries = 0;
    s_nextAutoMs = millis() + 5000;
}

int  lastState() { return s_last; }
bool waking() { return s_packetsLeft > 0 || s_watching; }

// --- Magic packet ----------------------------------------------------------------

static bool sendTo(int sock, const uint8_t* pkt, size_t len, IPAddress dst) {
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(WOL_UDP_PORT);
    a.sin_addr.s_addr = (uint32_t)dst;
    return sendto(sock, pkt, len, 0, (sockaddr*)&a, sizeof(a)) == (int)len;
}

// One round: every broadcast address we know. Raw socket because Arduino's
// WiFiUDP never sets SO_BROADCAST.
static int sendRound() {
    uint8_t pkt[6 + 16 * 6];
    memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) memcpy(pkt + 6 + i * 6, MAC, 6);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return 0;
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));

    IPAddress targets[3];
    int n = 0;
    targets[n++] = IPAddress(255, 255, 255, 255);
    IPAddress directed;
    if (directed.fromString(WOL_DIRECTED_BROADCAST)) targets[n++] = directed;
    IPAddress subnet = WiFi.broadcastIP();          // in case the network changed
    uint32_t sub = (uint32_t)subnet;
    if (sub && sub != (uint32_t)directed && sub != 0xFFFFFFFFu) targets[n++] = subnet;

    int sent = 0;
    for (int i = 0; i < n; i++) sent += sendTo(sock, pkt, sizeof(pkt), targets[i]);
    close(sock);
    return sent;
}

void wake(const char* why) {
    strlcpy(s_why, why, sizeof(s_why));
    s_packetsLeft = WOL_PACKETS;
    s_nextPacketMs = millis();
    s_watching = false;
}

// --- Reachability ------------------------------------------------------------------

bool check(uint16_t* port, uint32_t* ms) {
    if (port) *port = 0;
    if (!network::connected()) return false;
    IPAddress ip;
    if (!ip.fromString(s_ip)) return false;
    const uint16_t ports[2] = {WOL_CHECK_PORT, WOL_CHECK_PORT_ALT};
    for (uint16_t p : ports) {
        WiFiClient c;
        uint32_t t0 = millis();
        if (c.connect(ip, p, WOL_CONNECT_TIMEOUT_MS)) {
            c.stop();
            if (port) *port = p;
            if (ms) *ms = millis() - t0;
            s_last = 1;
            return true;
        }
    }
    s_last = 0;
    return false;
}

// --- Loop -------------------------------------------------------------------------------

void loop() {
    uint32_t now = millis();

    if (s_packetsLeft > 0 && (int32_t)(now - s_nextPacketMs) >= 0) {
        if (!network::connected()) {
            s_packetsLeft = 0;
            report("❌ Can't send the magic packet: the AuthKey has no WiFi.");
            return;
        }
        int sent = sendRound();
        s_packetsLeft--;
        s_nextPacketMs = now + 1000;
        logf("WOL", "magic packet round sent (%d address(es)), %d left", sent, s_packetsLeft);
        if (s_packetsLeft == 0) {
            logEvent("WoL sent (%s)", s_why);
            report("⏰ Magic packet sent %d× to %02x:%02x:%02x:%02x:%02x:%02x "
                   "(255.255.255.255 + %s). Watching %s for %d min…",
                   WOL_PACKETS, MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5],
                   WOL_DIRECTED_BROADCAST, WOL_SERVER_NAME, WOL_WATCH_SECS / 60);
            s_watching = true;
            s_wakeMs = now;
            s_nextWatchMs = now + WOL_WATCH_EVERY_SECS * 1000UL;
        }
        return;
    }

    // Long checks wait while a passkey prompt is up (the user is mid-sign-in).
    if (ctap::busy()) return;

    if (s_watching && (int32_t)(now - s_nextWatchMs) >= 0) {
        uint16_t port;
        if (check(&port)) {
            s_watching = false;
            s_downSinceMs = 0;
            s_autoTries = 0;
            logEvent("%s up after WoL", WOL_SERVER_NAME);
            report("🟢 %s is up (%lu s after the wake, port %u answered).", WOL_SERVER_NAME,
                   (unsigned long)((millis() - s_wakeMs) / 1000), port);
        } else if (now - s_wakeMs >= WOL_WATCH_SECS * 1000UL) {
            s_watching = false;
            logEvent("%s still down after WoL", WOL_SERVER_NAME);
            report("🔴 %s didn't come up within %d min. Check the BIOS (Deep Sleep Control = Disabled, "
                   "Wake on LAN = LAN Only) and that the PC still has power.", WOL_SERVER_NAME, WOL_WATCH_SECS / 60);
        } else {
            s_nextWatchMs = now + WOL_WATCH_EVERY_SECS * 1000UL;
        }
        return;
    }

    if (!s_auto || s_watching || (int32_t)(now - s_nextAutoMs) < 0) return;
    s_nextAutoMs = now + WOL_AUTO_CHECK_SECS * 1000UL;
    if (!network::connected()) return;
    if (check()) {
        if (s_downSinceMs) logf("WOL", "%s reachable again", WOL_SERVER_NAME);
        s_downSinceMs = 0;
        s_autoTries = 0;
        return;
    }
    if (!s_downSinceMs) { s_downSinceMs = now; return; }
    if (now - s_downSinceMs < (uint32_t)s_autoMin * 60000UL || s_autoTries >= WOL_AUTO_MAX_TRIES) return;
    s_autoTries++;
    s_downSinceMs = now;   // the next try (if needed) waits another N minutes
    report("⚠️ %s has been unreachable for %d min: sending a magic packet (auto-wake, try %d of %d).",
           WOL_SERVER_NAME, s_autoMin, s_autoTries, WOL_AUTO_MAX_TRIES);
    wake("auto-wake");
}

}  // namespace wol
