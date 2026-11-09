#include "net/telegram.h"
#include "config.h"
#include "core/log.h"
#include "fido/ctap2.h"
#include "net/network.h"
#include "net/portal.h"
#include "net/telegram_ca.h"
#include "net/wol.h"
#include "transport/hybrid.h"

#include <ArduinoJson.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <mbedtls/x509_crt.h>

namespace telegram {

#define MAX_CHATS       4
#define OUTBOX          3
#define MSG_MAX         320
#define RESP_MAX        2048                    // RAM is tight next to TLS; longer replies are skipped
#define POLL_STALL_MS   ((TG_LONG_POLL_SECS + 15) * 1000UL)
#define SEND_STALL_MS   15000UL

enum class St : uint8_t { Off, Idle, Polling, Sending };

struct Outgoing {
    long long chat;
    char      text[MSG_MAX];
};

static St               s_state = St::Off;
static WiFiClientSecure s_tls;
static bool             s_connected = false;
static long long        s_chats[MAX_CHATS];
static int              s_chatCount = 0;
static long long        s_offset = 0;            // next update_id to fetch
static uint32_t         s_nextTryMs = 0;
static uint32_t         s_backoffS = 0;
static uint32_t         s_reqMs = 0;
static char             s_err[64] = "";
static long long        s_lastIgnored = 0;

static Outgoing         s_out[OUTBOX];
static int              s_outHead = 0, s_outCount = 0;

static char             s_resp[RESP_MAX + 1];    // one HTTP response
static size_t           s_respLen = 0;

bool enabled() { return SECRET_TG_TOKEN[0] != '\0'; }
bool finderMode() { return enabled() && s_chatCount == 0; }
const char* lastError() { return s_err; }
long long lastIgnoredChat() { return s_lastIgnored; }

const char* stateStr() {
    if (!enabled()) return "off (no token in .env)";
    switch (s_state) {
        case St::Polling: return finderMode() ? "listening (chat-ID finder)" : "listening";
        case St::Sending: return "sending";
        default:          return s_connected ? "connected" : "disconnected";
    }
}

static void setError(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void setError(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s_err, sizeof(s_err), fmt, ap);
    va_end(ap);
    logf("TG", "%s", s_err);
}

static bool allowed(long long chat) {
    for (int i = 0; i < s_chatCount; i++) if (s_chats[i] == chat) return true;
    return false;
}

static void enqueue(long long chat, const char* text) {
    if (s_outCount == OUTBOX) {             // drop the oldest
        s_outHead = (s_outHead + 1) % OUTBOX;
        s_outCount--;
    }
    Outgoing& o = s_out[(s_outHead + s_outCount) % OUTBOX];
    o.chat = chat;
    strlcpy(o.text, text, sizeof(o.text));
    s_outCount++;
}

void notify(const char* text) {
    for (int i = 0; i < s_chatCount; i++) enqueue(s_chats[i], text);
}

static void hangUp() {
    if (s_connected) s_tls.stop();
    s_connected = false;
    if (s_state != St::Off) s_state = St::Idle;
    s_respLen = 0;
}

void releaseTls() {
    if (s_connected) logf("TG", "hanging up (TLS memory needed elsewhere)");
    hangUp();
}

// Exponential back-off (5 s .. 2 min), or a fixed wait for errors that won't
// fix themselves quickly (bad token).
static void backOff(uint32_t fixedSecs = 0) {
    hangUp();
    s_backoffS = s_backoffS ? s_backoffS * 2 : TG_BACKOFF_MIN_SECS;
    if (s_backoffS > TG_BACKOFF_MAX_SECS) s_backoffS = TG_BACKOFF_MAX_SECS;
    s_nextTryMs = millis() + (fixedSecs ? fixedSecs : s_backoffS) * 1000UL;
}

void init() {
    // TELEGRAM_CHAT_ID: one or more numeric IDs, comma-separated.
    const char* p = SECRET_TG_CHATS;
    while (*p && s_chatCount < MAX_CHATS) {
        char* end;
        long long id = strtoll(p, &end, 10);
        if (end == p) break;
        s_chats[s_chatCount++] = id;
        p = *end == ',' ? end + 1 : end;
    }
    if (!enabled()) {
        logf("TG", "no TELEGRAM_BOT_TOKEN in .env: bot off");
        return;
    }
    s_state = St::Idle;
    wol::setNotifier(notify);
    if (finderMode())
        logf("TG", "no TELEGRAM_CHAT_ID yet: send your bot any message, its chat ID is logged here");
    else
        logf("TG", "bot on, %d allowed chat(s)", s_chatCount);
}

// --- Commands ---------------------------------------------------------------------

static const char HELP[] =
    "AuthKey server control\n"
    "/wake – wake " WOL_SERVER_NAME " (wake-on-LAN), then tell you when it is up\n"
    "/status – 🟢 up or 🔴 down\n"
    "/autowake on|off [minutes] – wake it when unreachable that long (default 10)\n"
    "/setip <ip> – the server's address (DHCP can change it)\n"
    "/help – this list";

static void statusReply(long long chat) {
    uint16_t port;
    uint32_t ms = 0;
    char msg[MSG_MAX], autoLine[48];
    if (wol::autoWake()) snprintf(autoLine, sizeof(autoLine), "Auto-wake: on (%d min)", wol::autoWakeMinutes());
    else strlcpy(autoLine, "Auto-wake: off", sizeof(autoLine));
    if (wol::check(&port, &ms)) {
        snprintf(msg, sizeof(msg), "🟢 up – %s (%s) answers on port %u (%lu ms)\n%s", WOL_SERVER_NAME,
                 wol::serverIp(), port, (unsigned long)ms, autoLine);
    } else {
        snprintf(msg, sizeof(msg), "🔴 down – %s (%s): no answer on %d or %d%s\n%s", WOL_SERVER_NAME,
                 wol::serverIp(), WOL_CHECK_PORT, WOL_CHECK_PORT_ALT,
                 wol::waking() ? " (wake in progress)" : "", autoLine);
    }
    enqueue(chat, msg);
}

static void command(long long chat, const char* textIn) {
    char text[96];
    strlcpy(text, textIn, sizeof(text));
    char* arg = strchr(text, ' ');
    if (arg) { *arg++ = '\0'; while (*arg == ' ') arg++; }
    char* at = strchr(text, '@');          // "/wake@MyBot" in group chats
    if (at) *at = '\0';
    char msg[MSG_MAX];
    logf("TG", "command %s from chat %lld", text, chat);

    if (!strcmp(text, "/wake")) {
        wol::wake("/wake");                // reports itself once the packets are out
    } else if (!strcmp(text, "/status")) {
        statusReply(chat);
    } else if (!strcmp(text, "/autowake")) {
        if (arg && (!strncmp(arg, "on", 2) || !strncmp(arg, "off", 3))) {
            bool on = !strncmp(arg, "on", 2);
            int minutes = 0;
            const char* num = strchr(arg, ' ');
            if (num) minutes = atoi(num);
            wol::setAutoWake(on, minutes);
            logEvent("Auto-wake %s", on ? "ON" : "off");
        }
        if (wol::autoWake())
            snprintf(msg, sizeof(msg), "Auto-wake is ON: if %s is unreachable for %d min, I send a magic packet and tell you.",
                     WOL_SERVER_NAME, wol::autoWakeMinutes());
        else
            snprintf(msg, sizeof(msg), "Auto-wake is off. Turn on: /autowake on [minutes]");
        enqueue(chat, msg);
    } else if (!strcmp(text, "/setip")) {
        if (arg && *arg) {
            if (wol::setServerIp(arg)) snprintf(msg, sizeof(msg), "OK: %s is now %s (saved).", WOL_SERVER_NAME, wol::serverIp());
            else snprintf(msg, sizeof(msg), "That isn't an IPv4 address. Example: /setip 172.16.114.175");
        } else {
            snprintf(msg, sizeof(msg), "%s is at %s. Change: /setip <ip>", WOL_SERVER_NAME, wol::serverIp());
        }
        enqueue(chat, msg);
    } else if (!strcmp(text, "/help") || !strcmp(text, "/start")) {
        enqueue(chat, HELP);
    } else {
        enqueue(chat, "Unknown command. /help lists them.");
    }
}

static void handleUpdate(JsonObject u) {
    long long id = u["update_id"].as<long long>();
    if (id >= s_offset) s_offset = id + 1;
    JsonObject m = u["message"];
    if (m.isNull()) return;
    long long chat = m["chat"]["id"].as<long long>();
    const char* user = m["from"]["username"] | (m["from"]["first_name"] | "?");
    const char* text = m["text"] | "";

    if (finderMode()) {
        logf("TG", "chat ID %lld (from %s) sent \"%.40s\". Put TELEGRAM_CHAT_ID=%lld in .env and re-flash.",
             chat, user, text, chat);
        logEvent("TG chat ID %lld", chat);
        return;
    }
    if (!allowed(chat)) {
        s_lastIgnored = chat;
        logf("TG", "ignored message from chat %lld (%s)", chat, user);
        return;
    }
    // Telegram keeps undelivered messages for a day: a /wake sent while the
    // AuthKey was off must not start the server hours later.
    long long sent = m["date"].as<long long>();
    time_t now = network::now();
    if (now && sent && now - sent > TG_MAX_COMMAND_AGE_SECS) {
        logf("TG", "ignored %.20s from %lld: sent %lld s ago", text, chat, (long long)(now - sent));
        return;
    }
    if (text[0] == '/') command(chat, text);
    else enqueue(chat, "Commands only. /help lists them.");
}

// --- HTTP -------------------------------------------------------------------------------

// Parses s_resp once complete. Returns -1 while incomplete, else the HTTP
// status; `body` / `bodyLen` point into s_resp (de-chunked in place).
static int parseResponse(char** body, size_t* bodyLen, bool* keepAlive) {
    s_resp[s_respLen] = '\0';
    char* hdrEnd = strstr(s_resp, "\r\n\r\n");
    if (!hdrEnd) return -1;
    *hdrEnd = '\0';
    int status = 0;
    sscanf(s_resp, "HTTP/%*s %d", &status);
    long contentLen = -1;
    bool chunked = false;
    *keepAlive = true;
    for (char* line = strstr(s_resp, "\r\n"); line; line = strstr(line + 2, "\r\n")) {
        const char* h = line + 2;
        if (!strncasecmp(h, "Content-Length:", 15)) contentLen = atol(h + 15);
        else if (!strncasecmp(h, "Transfer-Encoding:", 18) && strcasestr(h, "chunked")) chunked = true;
        else if (!strncasecmp(h, "Connection:", 11) && strcasestr(h, "close")) *keepAlive = false;
    }
    *hdrEnd = '\r';
    char* b = hdrEnd + 4;
    size_t have = s_resp + s_respLen - b;
    if (!chunked) {
        if (contentLen < 0 || have < (size_t)contentLen) return -1;
        *body = b;
        *bodyLen = contentLen;
        return status;
    }
    // Chunked: complete once the zero-length chunk has arrived; join in place.
    if (!strstr(b, "\r\n0\r\n\r\n") && strncmp(b, "0\r\n\r\n", 5)) return -1;
    char* in = b;
    char* out = b;
    while (true) {
        long n = strtol(in, &in, 16);
        in = strstr(in, "\r\n");
        if (!in || n <= 0) break;
        in += 2;
        memmove(out, in, n);
        out += n;
        in += n + 2;
    }
    *body = b;
    *bodyLen = out - b;
    return status;
}

static bool connectTls() {
    // A TLS session peaks at ~54 KB here; trying with less just fails (as a
    // "certificate verification failed" when RSA can't allocate) and
    // fragments the heap further.
    if (ESP.getMaxAllocHeap() < TG_MIN_HEAP || ESP.getFreeHeap() < TG_MIN_FREE_HEAP) {
        setError("waiting for RAM (free %u, largest %u)", (unsigned)ESP.getFreeHeap(),
                 (unsigned)ESP.getMaxAllocHeap());
        return false;
    }
    s_tls.setCACert(TELEGRAM_ROOT_CA);
    s_tls.setHandshakeTimeout(10);
    logf("TG", "connecting to %s", TG_HOST);
    if (!s_tls.connect(TG_HOST, 443)) {
        char why[100] = "";
        int code = s_tls.lastError(why, sizeof(why));
        if (code == -0x2700 /* MBEDTLS_ERR_X509_CERT_VERIFY_FAILED */) {
            // Not bypassed: someone (e.g. TLS inspection) presented a certificate
            // that doesn't chain to Telegram's root.
            setError("certificate check FAILED (TLS inspection?)");
            logEvent("TG cert check failed");
        } else {
            setError("connect failed: %.40s", why[0] ? why : "no route / DNS");
        }
        s_tls.stop();
        return false;
    }
    s_connected = true;
    logf("TG", "connected (certificate verified)");
    return true;
}

static void sendPoll() {
    char req[256];
    snprintf(req, sizeof(req),
             "GET /bot%s/getUpdates?offset=%lld&limit=1&timeout=%d&allowed_updates=%%5B%%22message%%22%%5D HTTP/1.1\r\n"
             "Host: " TG_HOST "\r\nConnection: keep-alive\r\n\r\n",
             SECRET_TG_TOKEN, s_offset, TG_LONG_POLL_SECS);
    s_tls.print(req);
    memset(req, 0, sizeof(req));            // held the token
    s_respLen = 0;
    s_reqMs = millis();
    s_state = St::Polling;
}

static void sendMessage(const Outgoing& o) {
    JsonDocument doc;
    doc["chat_id"] = o.chat;
    doc["text"] = o.text;
    doc["disable_web_page_preview"] = true;
    String body;
    serializeJson(doc, body);
    char head[200];
    snprintf(head, sizeof(head),
             "POST /bot%s/sendMessage HTTP/1.1\r\nHost: " TG_HOST "\r\nConnection: keep-alive\r\n"
             "Content-Type: application/json\r\nContent-Length: %u\r\n\r\n",
             SECRET_TG_TOKEN, (unsigned)body.length());
    s_tls.print(head);
    s_tls.print(body);
    memset(head, 0, sizeof(head));
    s_respLen = 0;
    s_reqMs = millis();
    s_state = St::Sending;
}

// When the buffer can't hold a reply (a huge message), skip that update so
// the bot doesn't fetch it forever.
static void skipOversizedUpdate() {
    s_resp[s_respLen] = '\0';
    const char* p = strstr(s_resp, "\"update_id\":");
    if (p) s_offset = atoll(p + 12) + 1;
    setError("reply too large; skipped one update");
}

static void handlePoll(int status, char* body, size_t len) {
    if (status == 401 || status == 404) {
        setError("HTTP %d: bad TELEGRAM_BOT_TOKEN?", status);
        backOff(300);                       // no point hammering with a wrong token
        return;
    }
    if (status == 409) {                    // another poller or a webhook on this bot
        setError("HTTP 409: another program is polling this bot (or a webhook is set)");
        backOff();
        return;
    }
    if (status != 200) {
        setError("getUpdates HTTP %d", status);
        backOff();
        return;
    }
    JsonDocument doc;
    if (deserializeJson(doc, body, len)) {
        setError("bad JSON from Telegram");
        backOff();
        return;
    }
    s_backoffS = 0;
    s_err[0] = '\0';
    for (JsonObject u : doc["result"].as<JsonArray>()) handleUpdate(u);
}

static bool readAvailable() {
    while (s_tls.available() && s_respLen < RESP_MAX) {
        int n = s_tls.read((uint8_t*)s_resp + s_respLen, RESP_MAX - s_respLen);
        if (n <= 0) break;
        s_respLen += n;
    }
    return s_respLen < RESP_MAX;
}

// Something else is about to need TLS memory (campus portal refresh / login,
// hybrid sign-in) or the device is busy with a passkey prompt.
static bool mustYield() {
    if (hybrid::state() != hybrid::State::Idle) return true;
    if (portal::haveCredentials()) {
        // The portal's code is unchanged; the bot just steps aside before its
        // TLS requests: a login while offline, or the scheduled refresh / check
        // (also "Login now", which sets the countdown to 0).
        if (!portal::online() && portal::enabled() && !portal::paused()) return true;
        if (portal::secondsToNext() <= 3) return true;
    }
    return false;
}

// Diagnostics after a failed certificate check: connect once more WITHOUT
// verification only to print what certificate this network presents, then
// hang up. Nothing is sent over that connection (no token, no request).
static void describePeer() {
    IPAddress ip;
    WiFi.hostByName(TG_HOST, ip);
    WiFiClientSecure d;
    d.setInsecure();
    d.setHandshakeTimeout(10);
    if (!d.connect(TG_HOST, 443)) {
        char why[80] = "";
        int code = d.lastError(why, sizeof(why));
        logf("TG", "diagnostic connect to %s failed too (%d: %s), free heap %u, largest %u", ip.toString().c_str(),
             code, why, (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
        return;
    }
    const mbedtls_x509_crt* crt = d.getPeerCertificate();
    char subject[160] = "?", issuer[160] = "?";
    uint8_t fp[32];
    char fpHex[65] = "";
    if (crt) {
        mbedtls_x509_dn_gets(subject, sizeof(subject), &crt->subject);
        mbedtls_x509_dn_gets(issuer, sizeof(issuer), &crt->issuer);
    }
    if (d.getFingerprintSHA256(fp)) for (int i = 0; i < 32; i++) sprintf(fpHex + 2 * i, "%02x", fp[i]);
    // The chain as received, and mbedTLS's own verdict on it with our root.
    int depth = 0;
    for (const mbedtls_x509_crt* c = crt; c; c = c->next) {
        char sub[100] = "?";
        mbedtls_x509_dn_gets(sub, sizeof(sub), &c->subject);
        logf("TG", "  chain[%d]: %s", depth++, sub);
    }
    if (crt) {
        mbedtls_x509_crt ca;
        mbedtls_x509_crt_init(&ca);
        int rc = mbedtls_x509_crt_parse(&ca, (const unsigned char*)TELEGRAM_ROOT_CA, sizeof(TELEGRAM_ROOT_CA));
        uint32_t flags = 0;
        int vr = rc ? rc : mbedtls_x509_crt_verify((mbedtls_x509_crt*)crt, &ca, nullptr, TG_HOST, &flags, nullptr, nullptr);
        char info[200] = "";
        mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
        for (char* q = info; *q; q++) if (*q == '\n') *q = ';';
        logf("TG", "  verify: parse=%d result=%d flags=0x%08lx %s", rc, vr, (unsigned long)flags, info);
        mbedtls_x509_crt_free(&ca);
    }
    d.stop();
    logf("TG", "presented by %s:", ip.toString().c_str());
    logf("TG", "  subject: %s", subject);
    logf("TG", "  issuer:  %s", issuer);
    if (crt) logf("TG", "  valid:   %04d-%02d-%02d .. %04d-%02d-%02d", crt->valid_from.year, crt->valid_from.mon,
                  crt->valid_from.day, crt->valid_to.year, crt->valid_to.mon, crt->valid_to.day);
    logf("TG", "  sha256:  %s", fpHex);
}

bool ping(char* out, size_t cap) {
    if (!network::connected()) { snprintf(out, cap, "no WiFi"); return false; }
    if (s_connected) { snprintf(out, cap, "bot is connected right now (that already proves it works)"); return true; }
    uint32_t heapBefore = ESP.getFreeHeap();
    uint32_t t0 = millis();
    WiFiClientSecure c;
    c.setCACert(TELEGRAM_ROOT_CA);
    c.setHandshakeTimeout(10);
    if (!c.connect(TG_HOST, 443)) {
        char why[80] = "";
        int code = c.lastError(why, sizeof(why));
        snprintf(out, cap, "%s (%d: %s)", code == -0x2700 ? "certificate check FAILED" : "connect failed", code, why);
        if (code == -0x2700) describePeer();
        return false;
    }
    uint32_t handshake = millis() - t0;
    uint32_t heapDuring = ESP.getFreeHeap();
    c.print("GET /bot/getMe HTTP/1.1\r\nHost: " TG_HOST "\r\nConnection: close\r\n\r\n");
    char line[48] = "";
    uint32_t deadline = millis() + 5000;
    size_t n = 0;
    while (millis() < deadline && n < sizeof(line) - 1) {
        int ch = c.read();
        if (ch < 0) { delay(10); continue; }
        if (ch == '\r' || ch == '\n') break;
        line[n++] = (char)ch;
    }
    line[n] = '\0';
    c.stop();
    snprintf(out, cap, "certificate verified, TLS %lu ms, RAM used %lu bytes, reply: %s",
             (unsigned long)handshake, (unsigned long)(heapBefore - heapDuring), line);
    return true;
}

void loop() {
    if (s_state == St::Off) return;
    if (!network::connected()) { if (s_connected) hangUp(); return; }
    if (mustYield()) { if (s_connected) releaseTls(); return; }

    if (s_state == St::Polling || s_state == St::Sending) {
        if (!s_tls.connected() && !s_tls.available()) {
            logf("TG", "connection closed by the server");
            hangUp();
            s_nextTryMs = millis() + 2000;   // don't redo the handshake in a tight loop
            return;
        }
        if (!readAvailable()) {
            if (s_state == St::Polling) skipOversizedUpdate();
            backOff();
            return;
        }
        char* body;
        size_t len;
        bool keep;
        int status = parseResponse(&body, &len, &keep);
        if (status < 0) {
            uint32_t limit = s_state == St::Polling ? POLL_STALL_MS : SEND_STALL_MS;
            if (millis() - s_reqMs > limit) { setError("no reply from Telegram"); hangUp(); }
            // A reply is waiting to go out: abandon the long poll (updates
            // stay queued at Telegram until confirmed by the next offset).
            else if (s_state == St::Polling && s_outCount && !s_respLen) hangUp();
            return;
        }
        if (s_state == St::Polling) {
            handlePoll(status, body, len);
        } else {
            if (status != 200) setError("sendMessage HTTP %d", status);
            s_outHead = (s_outHead + 1) % OUTBOX;   // sent (or rejected: don't retry forever)
            s_outCount--;
        }
        s_respLen = 0;
        if (s_state == St::Polling || s_state == St::Sending) s_state = St::Idle;
        if (!keep) hangUp();
        return;
    }

    // Idle: connect if needed, then send a queued message or start a poll.
    if ((int32_t)(millis() - s_nextTryMs) < 0) return;
    if (!s_connected) {
        if (ctap::busy()) return;            // the handshake would stall a passkey prompt
        if (!connectTls()) { backOff(); return; }
    }
    if (s_outCount) sendMessage(s_out[s_outHead]);
    else sendPoll();
}

}  // namespace telegram
