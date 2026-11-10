#include "net/proxmox.h"
#include "config.h"
#include "core/log.h"
#include "core/mem.h"
#include "crypto/crypto.h"
#include "net/network.h"
#include "net/telegram.h"
#include "net/wol.h"
#include "transport/hybrid.h"

#include <ArduinoJson.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <memory>
#include <new>

namespace proxmox {

// machine = the wake-on-LAN machine's name; ip / port: the API address ("" =
// the machine's IP, port 8006); url: web UI link shown in Telegram (optional).
struct Cfg {
    const char* machine; const char* token; const char* fingerprint; const char* node;
    const char* ip; const char* port; const char* url;
};
#ifdef SECRET_PVE
static const Cfg CFGS[] = { SECRET_PVE };
static const int N = sizeof(CFGS) / sizeof(CFGS[0]);
#else
static const Cfg CFGS[1] = {{"", "", "", "", "", "", ""}};
static const int N = 0;
#endif

#define PVE_TIMEOUT_MS  10000
#define PVE_CONNECT_TIMEOUT_MS 4000              // TCP connect: the main loop waits meanwhile
#define MAX_GUESTS      24

static Preferences s_prefs;
static char        s_node[N ? N : 1][32];        // node name, from PVE_n_NODE or /nodes
static bool        s_justPinned[N ? N : 1];

void init() {
    s_prefs.begin("pve", false);
    for (int c = 0; c < N; c++) strlcpy(s_node[c], CFGS[c].node, sizeof(s_node[c]));
    if (N) logf("PVE", "%d Proxmox server(s) configured", N);
}

int count() { return N; }
const char* machine(int c) { return c >= 0 && c < N ? CFGS[c].machine : ""; }

int forHost(int wolIndex) {
    const wol::Host* h = wol::host(wolIndex);
    if (!h) return -1;
    for (int c = 0; c < N; c++) if (!strcasecmp(CFGS[c].machine, h->name)) return c;
    return -1;
}

int find(const char* m) {
    if (!m || !*m) return N ? 0 : -1;
    int w = wol::find(m);
    if (w >= 0) return forHost(w);
    for (int c = 0; c < N; c++) if (!strcasecmp(CFGS[c].machine, m)) return c;
    return -1;
}

// --- Certificate pinning -------------------------------------------------------------------

static bool parseFingerprint(const char* s, uint8_t out[32]) {
    int n = 0;
    for (; *s && n < 64; s++) {
        if (*s == ':' || *s == ' ') continue;
        int v = isdigit((unsigned char)*s) ? *s - '0' : (tolower(*s) >= 'a' && tolower(*s) <= 'f') ? tolower(*s) - 'a' + 10 : -1;
        if (v < 0) return false;
        if (n % 2 == 0) out[n / 2] = v << 4; else out[n / 2] |= v;
        n++;
    }
    return n == 64;
}

static String hexFp(const uint8_t fp[32], int bytes = 32) {
    String s;
    char b[4];
    for (int i = 0; i < bytes; i++) { snprintf(b, sizeof(b), i ? ":%02X" : "%02X", fp[i]); s += b; }
    return s;
}

static bool pinned(int c, uint8_t out[32]) {
    if (CFGS[c].fingerprint[0]) return parseFingerprint(CFGS[c].fingerprint, out);
    char key[8];
    snprintf(key, sizeof(key), "fp%d", c);
    return s_prefs.isKey(key) && s_prefs.getBytes(key, out, 32) == 32;
}

String pinInfo(int c) {
    if (c < 0 || c >= N) return "not configured";
    uint8_t fp[32];
    if (!pinned(c, fp)) return CFGS[c].fingerprint[0] ? "PVE_FINGERPRINT in .env is not valid hex" : "none yet (pinned on the first connection)";
    return hexFp(fp) + (CFGS[c].fingerprint[0] ? " (from .env)" : " (pinned on first use)");
}

void unpin(int c) {
    if (c < 0 || c >= N) return;
    char key[8];
    snprintf(key, sizeof(key), "fp%d", c);
    if (s_prefs.isKey(key)) s_prefs.remove(key);
    logEvent("PVE %s cert unpinned", CFGS[c].machine);
}

// --- HTTP over TLS --------------------------------------------------------------------------

// The response body as a Stream (Content-Length or chunked), for ArduinoJson.
class Body : public Stream {
public:
    Body(WiFiClientSecure& c, long len, bool chunked) : c_(c), left_(len), chunked_(chunked) {
        deadline_ = millis() + PVE_TIMEOUT_MS;
        setTimeout(50);
    }
    int available() override { return done_ ? 0 : 1; }
    int peek() override { return -1; }
    size_t write(uint8_t) override { return 0; }
    int read() override {
        if (done_) return -1;
        if (chunked_) {
            if (chunkLeft_ == 0) {
                long size = 0;
                int ch;
                while ((ch = raw()) >= 0 && ch != '\n') {
                    int v = isdigit(ch) ? ch - '0' : (tolower(ch) >= 'a' && tolower(ch) <= 'f') ? tolower(ch) - 'a' + 10 : -1;
                    if (v >= 0 && !ext_) size = size * 16 + v;
                    else if (ch == ';') ext_ = true;
                }
                ext_ = false;
                if (ch < 0 || size == 0) { if (size == 0) { raw(); raw(); } done_ = true; return -1; }
                chunkLeft_ = size;
            }
            int ch = raw();
            if (ch < 0) { done_ = true; return -1; }
            if (--chunkLeft_ == 0) { raw(); raw(); }       // CRLF after the chunk
            return ch;
        }
        if (left_ == 0) { done_ = true; return -1; }
        int ch = raw();
        if (ch < 0) { done_ = true; return -1; }
        if (left_ > 0) left_--;
        return ch;
    }
    void drain() { while (read() >= 0) {} }

private:
    int raw() {
        while (true) {
            int ch = c_.read();
            if (ch >= 0) return ch;
            if (!c_.connected() && !c_.available()) return -1;
            if ((int32_t)(millis() - deadline_) > 0) return -1;
            delay(1);
        }
    }
    WiFiClientSecure& c_;
    long     left_;          // -1: until the connection closes
    bool     chunked_;
    long     chunkLeft_ = 0;
    bool     ext_ = false;
    bool     done_ = false;
    uint32_t deadline_;
};

class Api {
public:
    explicit Api(int c) : c_(c) {}
    ~Api() { close(); }

    bool open(String& err) {
        if (open_ && tls_.connected()) return true;
        close();
        const char* name = CFGS[c_].machine;
        const wol::Host* h = wol::host(wol::find(name));
        port_ = atoi(CFGS[c_].port) > 0 ? atoi(CFGS[c_].port) : 8006;
        const char* addr = CFGS[c_].ip[0] ? CFGS[c_].ip : h ? h->ip : "";
        if (!addr[0] || !ip_.fromString(addr)) {
            err = h ? String(name) + " has no IP set (/sethost " + name + " ip …)"
                    : String("no IP for ") + name + " (PROXMOX_HOST_IP in .env)";
            return false;
        }
        if (!network::connected()) { err = "the AuthKey has no WiFi"; return false; }
        if (hybrid::state() != hybrid::State::Idle) { err = "busy with a passkey sign-in; try again in a minute"; return false; }
        // The bot's session normally stays up next to this one; it only makes
        // room when RAM is short.
        if (!mem::roomForTls()) telegram::releaseTls();
        if (!mem::roomForTls()) {
            err = String("not enough RAM for TLS right now (free ") + mem::freeHeap() + ")";
            return false;
        }
        tls_.setInsecure();                    // self-signed: checked by the pin below instead
        tls_.setHandshakeTimeout(10);
        uint32_t failsBefore = mem::failures();
        bool ok = tls_.connect(ip_, port_, PVE_CONNECT_TIMEOUT_MS);
        char why[80] = "";
        if (!ok) tls_.lastError(why, sizeof(why));
        if (!ok && mem::failures() != failsBefore) {
            // An allocation failed half-way: once more with the bot's RAM too.
            tls_.stop();
            telegram::releaseTls();
            delay(100);
            why[0] = '\0';
            ok = tls_.connect(ip_, port_, PVE_CONNECT_TIMEOUT_MS);
            if (!ok) tls_.lastError(why, sizeof(why));
        }
        if (!ok) {
            err = String("can't reach ") + name + " (" + ip_.toString() + ":" + port_ + "): " + (why[0] ? why : "no answer");
            tls_.stop();
            return false;
        }
        uint8_t got[32], want[32];
        if (!tls_.getFingerprintSHA256(got)) { err = "no server certificate"; close(); return false; }
        if (pinned(c_, want)) {
            if (!crypto::equal(got, want, 32)) {
                err = String("❌ ") + name + "'s certificate is not the pinned one (now " + hexFp(got, 8) +
                      "…). Nothing was sent. If you renewed it: /pve " + name + " unpin (needs OK on the AuthKey).";
                logEvent("PVE %s cert mismatch", name);
                close();
                return false;
            }
        } else if (CFGS[c_].fingerprint[0]) {
            err = "PVE_FINGERPRINT in .env is not 32 hex bytes";
            close();
            return false;
        } else {
            char key[8];
            snprintf(key, sizeof(key), "fp%d", c_);
            s_prefs.putBytes(key, got, 32);
            s_justPinned[c_] = true;
            logEvent("PVE %s cert pinned", name);
        }
        open_ = true;
        return true;
    }

    // Returns the HTTP status (0: no response; `err` says why). For 200 the
    // JSON goes through `filter` into `doc`.
    int call(const char* method, const char* path, const char* form, JsonDocument* doc, const JsonDocument* filter,
             String& err) {
        for (int attempt = 0; attempt < 2; attempt++) {
            if (!open(err)) return 0;
            send(method, path, form);
            int status = readHead(err);
            if (status == 0 && attempt == 0) { close(); continue; }   // keep-alive closed by the server: retry once
            if (status == 0) return 0;
            Body body(tls_, contentLen_, chunked_);
            if (status == 200 && doc) {
                DeserializationError e = filter ? deserializeJson(*doc, body, DeserializationOption::Filter(*filter))
                                                : deserializeJson(*doc, body);
                if (e) { err = String("bad JSON from Proxmox (") + e.c_str() + ")"; close(); return 0; }
            }
            body.drain();
            if (status != 200) err = describe(status);
            if (closeAfter_) close();
            return status;
        }
        return 0;
    }

private:
    void close() {
        if (open_ || tls_.connected()) tls_.stop();
        open_ = false;
    }

    void send(const char* method, const char* path, const char* form) {
        char head[360];
        int n = snprintf(head, sizeof(head),
                         "%s /api2/json%s HTTP/1.1\r\nHost: %s:%d\r\nAuthorization: PVEAPIToken=%s\r\n"
                         "Connection: keep-alive\r\nAccept: application/json\r\n",
                         method, path, ip_.toString().c_str(), port_, CFGS[c_].token);
        if (form) n += snprintf(head + n, sizeof(head) - n,
                                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %u\r\n",
                                (unsigned)strlen(form));
        else if (!strcmp(method, "POST")) n += snprintf(head + n, sizeof(head) - n, "Content-Length: 0\r\n");
        snprintf(head + n, sizeof(head) - n, "\r\n");
        tls_.print(head);
        if (form) tls_.print(form);
        crypto::wipe(head, sizeof(head));      // held the token
    }

    bool readLine(char* buf, size_t cap, uint32_t deadline) {
        size_t n = 0;
        while ((int32_t)(millis() - deadline) < 0) {
            int ch = tls_.read();
            if (ch < 0) {
                if (!tls_.connected() && !tls_.available()) break;
                delay(1);
                continue;
            }
            if (ch == '\n') { buf[n] = '\0'; if (n && buf[n - 1] == '\r') buf[n - 1] = '\0'; return true; }
            if (n < cap - 1) buf[n++] = (char)ch;
        }
        buf[n] = '\0';
        return false;
    }

    int readHead(String& err) {
        uint32_t deadline = millis() + PVE_TIMEOUT_MS;
        char line[160];
        if (!readLine(line, sizeof(line), deadline)) { err = "no reply from Proxmox"; return 0; }
        int status = 0;
        char* sp = strchr(line, ' ');
        if (sp) status = atoi(sp + 1);
        reason_ = sp && strchr(sp + 1, ' ') ? String(strchr(sp + 1, ' ') + 1) : String();
        contentLen_ = -1;
        chunked_ = false;
        closeAfter_ = false;
        while (readLine(line, sizeof(line), deadline) && line[0]) {
            if (!strncasecmp(line, "Content-Length:", 15)) contentLen_ = atol(line + 15);
            else if (!strncasecmp(line, "Transfer-Encoding:", 18) && strcasestr(line, "chunked")) chunked_ = true;
            else if (!strncasecmp(line, "Connection:", 11) && strcasestr(line, "close")) closeAfter_ = true;
        }
        if (contentLen_ < 0 && !chunked_) closeAfter_ = true;   // body runs to the end of the connection
        if (!status) err = "unexpected reply from Proxmox";
        return status;
    }

    String describe(int status) {
        String why = reason_.length() ? reason_ : String("HTTP ") + status;
        if (status == 401) return "token rejected (" + why + "): check PVE_TOKEN in .env";
        if (status == 403) return "permission denied: " + why + " (give the token's role that privilege)";
        return why;
    }

    int              c_;
    WiFiClientSecure tls_;
    bool             open_ = false;
    IPAddress        ip_;
    int              port_ = 8006;
    long             contentLen_ = -1;
    bool             chunked_ = false, closeAfter_ = false;
    String           reason_;
};

// --- Helpers ----------------------------------------------------------------------------------

static bool ensureNode(Api& api, int c, String& err) {
    if (s_node[c][0]) return true;
    JsonDocument f;
    f["data"][0]["node"] = true;
    JsonDocument d;
    if (api.call("GET", "/nodes", nullptr, &d, &f, err) != 200) return false;
    const char* pick = d["data"][0]["node"] | "";
    for (JsonObject o : d["data"].as<JsonArray>())
        if (!strcasecmp(o["node"] | "", CFGS[c].machine)) pick = o["node"];
    if (!*pick) { err = "Proxmox listed no nodes"; return false; }
    strlcpy(s_node[c], pick, sizeof(s_node[c]));
    return true;
}

static String path(int c, const char* rest) { return String("/nodes/") + s_node[c] + rest; }

static String gb(double bytes) {
    char b[16];
    snprintf(b, sizeof(b), bytes >= 1e12 ? "%.1f TB" : "%.1f GB", bytes >= 1e12 ? bytes / 1099511627776.0 : bytes / 1073741824.0);
    return b;
}

static String dur(long s) {
    char b[24];
    if (s < 3600) snprintf(b, sizeof(b), "%ld min", s / 60);
    else if (s < 2 * 86400) snprintf(b, sizeof(b), "%ld h %ld min", s / 3600, s % 3600 / 60);
    else snprintf(b, sizeof(b), "%ld d %ld h", s / 86400, s % 86400 / 3600);
    return b;
}

static String clock(time_t t) {
    char b[16];
    struct tm lt;
    localtime_r(&t, &lt);
    strftime(b, sizeof(b), "%a %H:%M", &lt);
    return b;
}

static String pinNotice(int c) {
    if (!s_justPinned[c]) return String();
    s_justPinned[c] = false;
    uint8_t fp[32];
    pinned(c, fp);
    return String("📌 First connection: pinned ") + CFGS[c].machine + "'s certificate, SHA-256\n" + hexFp(fp) +
           "\nCompare it with Proxmox → " + s_node[c] + " → System → Certificates (pve-ssl.pem). "
           "Any other certificate will be refused.\n\n";
}

static bool loadGuests(Api& api, int c, Guest* list, int cap, int* n, String& err) {
    *n = 0;
    JsonDocument f;
    f["data"][0]["vmid"] = true;
    f["data"][0]["name"] = true;
    f["data"][0]["status"] = true;
    for (int kind = 0; kind < 2; kind++) {
        JsonDocument d;
        String e;
        int st = api.call("GET", path(c, kind ? "/lxc" : "/qemu").c_str(), nullptr, &d, &f, e);
        if (st != 200) { err += String(kind ? "containers: " : "VMs: ") + e + "\n"; continue; }
        for (JsonObject o : d["data"].as<JsonArray>()) {
            if (*n >= cap) break;
            Guest& g = list[(*n)++];
            g.vmid = o["vmid"].as<int>();
            strlcpy(g.name, o["name"] | "", sizeof(g.name));
            g.lxc = kind == 1;
            g.running = !strcmp(o["status"] | "", "running");
        }
    }
    // By ID.
    for (int i = 1; i < *n; i++)
        for (int j = i; j > 0 && list[j - 1].vmid > list[j].vmid; j--) { Guest t = list[j]; list[j] = list[j - 1]; list[j - 1] = t; }
    return err.length() == 0 || *n > 0;
}

// Last vzdump tasks (newest first). `since` > 0: only those that started after it.
static String backupLines(Api& api, int c, time_t since, int max) {
    JsonDocument f;
    f["data"][0]["starttime"] = true;
    f["data"][0]["endtime"] = true;
    f["data"][0]["status"] = true;
    f["data"][0]["id"] = true;
    JsonDocument d;
    String e;
    int st = api.call("GET", path(c, "/tasks?typefilter=vzdump&limit=5&source=all").c_str(), nullptr, &d, &f, e);
    if (st != 200) return "💾 Backups: " + e + "\n";
    String s;
    int shown = 0;
    for (JsonObject t : d["data"].as<JsonArray>()) {
        long start = t["starttime"] | 0L;
        if (since && start < since - 120) continue;
        if (shown++ >= max) break;
        long end = t["endtime"] | 0L;
        const char* status = t["status"] | "";
        const char* id = t["id"] | "";
        String what = *id ? String(" (guest ") + id + ")" : String();
        if (!end || !*status) s += "💾 Backup ⏳ running since " + clock(start) + what + "\n";
        else if (!strcmp(status, "OK")) s += "💾 Backup ✅ " + clock(start) + ", " + dur(end - start) + what + "\n";
        else if (!strncmp(status, "WARNINGS", 8)) s += "💾 Backup ⚠️ " + clock(start) + ", " + status + what + "\n";
        else s += "💾 Backup ❌ " + clock(start) + ": " + status + what + "\n";
    }
    if (!shown) s = since ? "💾 No backup ran in the window.\n" : "💾 No backups found.\n";
    return s;
}

static String updateLine(Api& api, int c) {
    JsonDocument f;
    f["data"][0]["Package"] = true;
    JsonDocument d;
    String e;
    int st = api.call("GET", path(c, "/apt/update").c_str(), nullptr, &d, &f, e);
    if (st != 200) return "📦 Updates: " + e + "\n";
    int n = d["data"].as<JsonArray>().size();
    return n ? String("📦 ") + n + " package update(s) pending on the host\n" : String("📦 Host is up to date\n");
}

// --- Public calls ----------------------------------------------------------------------------

bool summary(int c, String& out) {
    out = String();
    if (c < 0 || c >= N) { out = "No Proxmox server configured (PROXMOX_TOKEN_ID / PROXMOX_TOKEN in .env)."; return false; }
    Api api(c);
    String err;
    if (!ensureNode(api, c, err)) { out = pinNotice(c) + "❌ " + err; return false; }

    JsonDocument f;
    JsonObject fd = f["data"].to<JsonObject>();
    for (const char* k : {"cpu", "loadavg", "uptime", "pveversion"}) fd[k] = true;
    fd["memory"]["used"] = true;
    fd["memory"]["total"] = true;
    fd["rootfs"]["used"] = true;
    fd["rootfs"]["total"] = true;
    JsonDocument d;
    if (api.call("GET", path(c, "/status").c_str(), nullptr, &d, &f, err) != 200) { out = pinNotice(c) + "❌ " + err; return false; }
    JsonObject s = d["data"];
    String ver = s["pveversion"] | "";
    int a = ver.indexOf('/'), b = ver.indexOf('/', a + 1);
    if (a >= 0) ver = ver.substring(a + 1, b > a ? b : ver.length());
    char line[160];
    snprintf(line, sizeof(line), "🖥 %s · Proxmox VE %s · up %s\n", s_node[c], ver.c_str(), dur(s["uptime"] | 0L).c_str());
    out = pinNotice(c) + line;
    snprintf(line, sizeof(line), "CPU %.0f %% · load %s · RAM %s / %s · disk %s / %s\n",
             (s["cpu"] | 0.0) * 100, (const char*)(s["loadavg"][0] | "?"),
             gb(s["memory"]["used"] | 0.0).c_str(), gb(s["memory"]["total"] | 0.0).c_str(),
             gb(s["rootfs"]["used"] | 0.0).c_str(), gb(s["rootfs"]["total"] | 0.0).c_str());
    out += line;

    // On the heap for this call only (not static: RAM is short; not on the small loop stack).
    std::unique_ptr<Guest[]> g(new (std::nothrow) Guest[MAX_GUESTS]);
    if (!g) { out += "(out of memory for the guest list)\n"; return true; }
    int n = 0, running = 0;
    String gerr;
    loadGuests(api, c, g.get(), MAX_GUESTS, &n, gerr);
    for (int i = 0; i < n; i++) running += g[i].running;
    out += String("\nGuests (") + running + " of " + n + " running):\n";
    for (int i = 0; i < n; i++)
        out += String(g[i].running ? "🟢 " : "⚪ ") + g[i].vmid + " " + g[i].name + (g[i].lxc ? " (CT)" : "") + "\n";
    out += gerr;
    out += "\n" + backupLines(api, c, 0, 2) + updateLine(api, c);
    if (CFGS[c].url[0]) out += String("🌐 ") + CFGS[c].url + "\n";
    return true;
}

bool guests(int c, Guest* list, int cap, int* n, String& err) {
    *n = 0;
    if (c < 0 || c >= N) { err = "no Proxmox server configured"; return false; }
    Api api(c);
    if (!ensureNode(api, c, err)) return false;
    return loadGuests(api, c, list, cap, n, err);
}

bool nodePower(int c, const char* command, String& out) {
    if (c < 0 || c >= N) { out = "no Proxmox server configured"; return false; }
    Api api(c);
    String err;
    if (!ensureNode(api, c, err)) { out = pinNotice(c) + "❌ " + err; return false; }
    String form = String("command=") + command;
    int st = api.call("POST", path(c, "/status").c_str(), form.c_str(), nullptr, nullptr, err);
    if (st != 200) { out = String("❌ ") + command + " refused: " + err; return false; }
    logEvent("PVE %s %s", s_node[c], command);
    out = String("OK: ") + s_node[c] + " is going to " + command + ".";
    return true;
}

bool guestPower(int c, int vmid, const char* action, String& out) {
    if (c < 0 || c >= N) { out = "no Proxmox server configured"; return false; }
    Api api(c);
    String err;
    if (!ensureNode(api, c, err)) { out = pinNotice(c) + "❌ " + err; return false; }
    std::unique_ptr<Guest[]> g(new (std::nothrow) Guest[MAX_GUESTS]);
    if (!g) { out = "❌ out of memory"; return false; }
    int n = 0;
    loadGuests(api, c, g.get(), MAX_GUESTS, &n, err);
    const Guest* found = nullptr;
    for (int i = 0; i < n; i++) if (g[i].vmid == vmid) found = &g[i];
    if (!found) { out = String("No guest ") + vmid + " on " + s_node[c] + "."; return false; }
    String p = path(c, found->lxc ? "/lxc/" : "/qemu/") + vmid + "/status/" + action;
    int st = api.call("POST", p.c_str(), nullptr, nullptr, nullptr, err);
    if (st != 200) { out = String("❌ ") + action + " " + vmid + " refused: " + err; return false; }
    logEvent("PVE %d %s", vmid, action);
    out = String("OK: ") + action + " " + vmid + " (" + found->name + ") started on " + s_node[c] + ".";
    return true;
}

bool maintenanceReport(int c, time_t since, String& out) {
    out = String();
    if (c < 0 || c >= N) return false;
    Api api(c);
    String err;
    if (!ensureNode(api, c, err)) { out = "Proxmox: " + err + "\n"; return false; }
    JsonDocument f;
    f["data"]["uptime"] = true;
    JsonDocument d;
    if (api.call("GET", path(c, "/status").c_str(), nullptr, &d, &f, err) == 200) {
        long up = d["data"]["uptime"] | 0L;
        time_t now = network::now();
        if (now && up && now - up >= since - 60) out += "🔁 Host restarted at " + clock(now - up) + "\n";
        else out += "⏱ Host up " + dur(up) + " (no restart)\n";
    }
    out = pinNotice(c) + out + backupLines(api, c, since, 3) + updateLine(api, c);
    return true;
}

}  // namespace proxmox
