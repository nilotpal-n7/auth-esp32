#include "net/telegram.h"
#include "config.h"
#include "cli/cli.h"
#include "core/approval.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "fido/ctap2.h"
#include "net/network.h"
#include "net/portal.h"
#include "net/proxmox.h"
#include "net/telegram_ca.h"
#include "net/wol.h"
#include "core/backup.h"
#include "totp/totp.h"
#include "transport/hybrid.h"

#include <ArduinoJson.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <mbedtls/x509_crt.h>

namespace telegram {

#define MAX_CHATS       4
#define OUTBOX          6                       // queued requests (texts live on the heap)
#define RESP_MAX        3072                    // RAM is tight next to TLS; longer replies are skipped
#define POLL_STALL_MS   ((TG_LONG_POLL_SECS + 15) * 1000UL)
#define SEND_STALL_MS   15000UL

enum class St : uint8_t { Off, Idle, Polling, Sending };
enum class Out : uint8_t { Message, Edit, Answer, Commands };

struct Outgoing {
    Out       type;
    long long chat;
    String    text;      // message text / setMyCommands body
    String    extra;     // reply_markup JSON / callback query id
    long      msgId;     // Edit: the message to replace
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
static bool             s_commandsSet = false;   // setMyCommands sent this boot

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

// --- Replies, buttons ---------------------------------------------------------------

static bool s_sim = false;                       // replies go to the console (tg sim)

static void push(Out type, long long chat, const String& text, const String& extra, long msgId = 0) {
    if (s_outCount == OUTBOX) {                  // drop the oldest
        s_out[s_outHead].text = String();
        s_out[s_outHead].extra = String();
        s_outHead = (s_outHead + 1) % OUTBOX;
        s_outCount--;
    }
    Outgoing& o = s_out[(s_outHead + s_outCount) % OUTBOX];
    o.type = type;
    o.chat = chat;
    o.text = text;
    o.extra = extra;
    o.msgId = msgId;
    s_outCount++;
}

static void reply(long long chat, String text, const String& markup = String()) {
    if (text.length() > 3800) { text.remove(3800); text += "\n…"; }
    if (s_sim) {
        consoleWrite("[bot] ");
        consoleWrite(text.c_str());
        consoleWrite("\n");
        if (markup.length()) { consoleWrite("[buttons] "); consoleWrite(markup.c_str()); consoleWrite("\n"); }
        return;
    }
    push(Out::Message, chat, text, markup);
}

// A "screen" (machine details, switches): edits the message whose button was
// pressed instead of adding a new one.
static long s_editMsg = 0;
static void view(long long chat, String text, const String& markup) {
    if (!s_editMsg || s_sim) { reply(chat, text, markup); return; }
    if (text.length() > 3800) { text.remove(3800); text += "\n…"; }
    push(Out::Edit, chat, text, markup, s_editMsg);
}

void notify(const char* text) {
    for (int i = 0; i < s_chatCount; i++) push(Out::Message, s_chats[i], text, String());
}

static int s_notifyLevel = 1;
// Alerts (server down / up, maintenance, backup reminders): muted by /notify off.
static void alertNotify(const char* text) {
    if (s_notifyLevel > 0) notify(text);
    else logf("TG", "alert not sent (notifications off)");
}

// Inline keyboard: two buttons per row; a button sends its command back.
struct Buttons {
    JsonDocument doc;
    JsonArray rows;
    JsonArray row;
    int inRow = 0;
    Buttons() { rows = doc["inline_keyboard"].to<JsonArray>(); }
    void add(const String& label, const String& command, int perRow = 2) {
        if (row.isNull() || inRow >= perRow) { row = rows.add<JsonArray>(); inRow = 0; }
        JsonObject b = row.add<JsonObject>();
        b["text"] = label;
        b["callback_data"] = command.substring(0, 64);
        inRow++;
    }
    void newRow() { inRow = 99; }
    String json() { String s; serializeJson(doc, s); return s; }
};

// --- Settings kept by the bot ------------------------------------------------------------

static Preferences s_prefs;
static bool s_remoteCodes = false;

int  notifyLevel() { return s_notifyLevel; }
const char* notifyLevelName(int l) { return l <= 0 ? "off" : l == 1 ? "important" : "all"; }
void setNotifyLevel(int l) {
    s_notifyLevel = l < 0 ? 0 : l > 2 ? 2 : l;
    s_prefs.putInt("notify", s_notifyLevel);
}
bool remoteCodes() { return s_remoteCodes; }
void setRemoteCodes(bool on) {
    s_remoteCodes = on;
    s_prefs.putBool("codes", on);
}

// --- Remote commands that need OK on the device ----------------------------------------

static struct {
    bool      active;
    bool      sim;
    long long chat;
    String    line;
} s_remote;

static void runAndReply(long long chat, const String& line) {
    String out;
    cli::run(line.c_str(), &out);
    out.trim();
    reply(chat, "$ " + line + "\n" + (out.length() ? out : String("(done, no output)")));
}

static void onRemoteApproval(bool approved, void*) {
    bool prev = s_sim;
    s_sim = s_remote.sim;
    if (approved) runAndReply(s_remote.chat, s_remote.line);
    else reply(s_remote.chat, "❌ Not approved on the AuthKey: " + s_remote.line);
    s_sim = prev;
    s_remote.active = false;
    s_remote.line = String();
}

// Runs a console line now, or after OK on the device if it is sensitive.
static void runConsole(long long chat, const String& line) {
    if (!cli::sensitive(line.c_str())) { runAndReply(chat, line); return; }
    if (s_remote.active ||
        !approval::ask("REMOTE COMMAND?", line.c_str(), "from Telegram", false, onRemoteApproval, nullptr)) {
        reply(chat, "The AuthKey is waiting for another confirmation; try again in a moment.");
        return;
    }
    s_remote.active = true;
    s_remote.sim = s_sim;
    s_remote.chat = chat;
    s_remote.line = line;
    reply(chat, "🔐 \"" + line + "\" needs OK on the AuthKey (30 s).");
}

// --- Wake-on-LAN helpers -------------------------------------------------------------------

static String hostLine(int i) {
    const wol::Host* h = wol::host(i);
    int st = wol::lastState(i);
    String s = wol::waking(i) ? "⏳ " : st > 0 ? "🟢 " : st == 0 ? "🔴 " : "⚪ ";
    s += h->name;
    s += h->ip[0] ? String(" (") + h->ip + ")" : String(" (no IP)");
    uint32_t age = wol::lastCheckAgeS(i);
    if (wol::waking(i)) s += " waking";
    else if (age != UINT32_MAX) s += String(", checked ") + (age < 120 ? String(age) + " s" : String(age / 60) + " min") + " ago";
    if (h->autoWake) s += String(", auto-wake ") + h->autoMin + " min";
    if (wol::paused(i)) s += ", ⏸ paused";
    if (wol::inMaintenance(i)) s += ", 🛠 maintenance";
    return s;
}

static int hostArg(long long chat, const char* arg) {
    int i = wol::find(arg);
    if (i < 0) reply(chat, String("No machine \"") + arg + "\". /hosts lists them.");
    return i;
}

// /status for every machine runs one check per loop pass (each may block ~3 s).
static struct {
    bool      active;
    bool      sim;
    long long chat;
    int       next;
    String    text;
} s_job;

static void stepStatusJob() {
    if (!s_job.active || ctap::busy()) return;
    int i = s_job.next++;
    if (i < wol::count()) {
        const wol::Host* h = wol::host(i);
        uint16_t port;
        uint32_t ms = 0;
        if (!h->ip[0]) s_job.text += String("⚪ ") + h->name + ": no IP set\n";
        else if (wol::check(i, &port, &ms)) s_job.text += String("🟢 up – ") + h->name + " (" + h->ip + ", port " + port + ", " + ms + " ms)\n";
        else s_job.text += String("🔴 down – ") + h->name + " (" + h->ip + ")" + (wol::waking(i) ? ", waking" : "") + "\n";
        return;
    }
    bool prev = s_sim;
    s_sim = s_job.sim;
    if (!wol::enabled()) s_job.text += "(wake-on-LAN is off: /wol on)";
    reply(s_job.chat, s_job.text);
    s_sim = prev;
    s_job.active = false;
    s_job.text = String();
}

// --- Commands --------------------------------------------------------------------------------

typedef void (*Handler)(long long chat, char* arg);
struct Command {
    const char* name;
    const char* args;
    const char* help;
    Handler     fn;
};
extern const Command COMMANDS[];
extern const int COMMAND_COUNT;

static void cmdHelp(long long chat, char*) {
    String s = "AuthKey remote control\n";
    for (int i = 0; i < COMMAND_COUNT; i++) {
        s += String("/") + COMMANDS[i].name + (COMMANDS[i].args[0] ? String(" ") + COMMANDS[i].args : String()) +
             " – " + COMMANDS[i].help + "\n";
    }
    s += "\nRisky actions (auto-approve on, deleting keys, raw CTAP, …) wait for OK on the AuthKey.";
    reply(chat, s);
}

static void cmdMenu(long long chat, char*) {
    Buttons b;
    b.add("📊 Status (all)", "/status");
    b.add("🖥 Machines", "/hosts");
    for (int i = 0; i < wol::count(); i++) b.add(String("⏰ Wake ") + wol::host(i)->name, String("/wake ") + wol::host(i)->name);
    b.newRow();
    if (proxmox::count()) b.add("📊 Proxmox", "/pve");
    if (proxmox::count()) b.add("🧩 VMs / containers", "/vm");
    b.add("ℹ️ Device info", "/info");
    b.add("📜 Event log", "/log");
    b.add("🌐 Campus login", "/portal login");
    b.add("🌐 Campus status", "/portal");
    b.add("⚙️ Switches", "/set");
    b.add(String("🔔 Notify: ") + notifyLevelName(s_notifyLevel), "/notify");
    reply(chat, "What do you want to do?", b.json());
}

static void cmdHosts(long long chat, char*) {
    if (!wol::count()) { reply(chat, "No machines yet. /addhost <name> <mac> [ip] [ports]"); return; }
    String s = String("Machines (wake-on-LAN ") + (wol::enabled() ? "on" : "OFF") + "):\n";
    Buttons b;
    for (int i = 0; i < wol::count(); i++) {
        s += String(i + 1) + ". " + hostLine(i) + "\n";
        b.add(String("🖥 ") + wol::host(i)->name + " ›", String("/host ") + wol::host(i)->name);
        b.add(String("⏰ Wake ") + wol::host(i)->name, String("/wake ") + wol::host(i)->name);
    }
    s += "\nTap a machine for auto-wake, alerts, pause and maintenance.";
    view(chat, s, b.json());
}

static void cmdWake(long long chat, char* arg) {
    if (!wol::enabled()) { reply(chat, "Wake-on-LAN is off. /wol on"); return; }
    if (!wol::count()) { reply(chat, "No machines yet. /addhost <name> <mac> [ip] [ports]"); return; }
    if (!*arg && wol::count() > 1) {
        Buttons b;
        for (int i = 0; i < wol::count(); i++) b.add(String("⏰ ") + wol::host(i)->name, String("/wake ") + wol::host(i)->name);
        b.add("⏰ All", "/wake all");
        reply(chat, "Which machine?", b.json());
        return;
    }
    if (!strcasecmp(arg, "all")) {
        for (int i = 0; i < wol::count(); i++) wol::wake(i, "/wake all");
        reply(chat, String("Waking ") + wol::count() + " machine(s)…");
        return;
    }
    int i = *arg ? hostArg(chat, arg) : 0;
    if (i < 0) return;
    wol::wake(i, "/wake");
    if (s_sim) reply(chat, String("Waking ") + wol::host(i)->name + " (reports follow as notifications).");
}

static void cmdStatus(long long chat, char* arg) {
    if (*arg && strcasecmp(arg, "all")) {
        int i = hostArg(chat, arg);
        if (i < 0) return;
        const wol::Host* h = wol::host(i);
        uint16_t port;
        uint32_t ms = 0;
        if (!h->ip[0]) reply(chat, String("⚪ ") + h->name + " has no IP set: /sethost " + h->name + " ip <address>");
        else if (wol::check(i, &port, &ms)) reply(chat, String("🟢 up – ") + h->name + " (" + h->ip + ") answers on port " + port + " (" + ms + " ms)");
        else reply(chat, String("🔴 down – ") + h->name + " (" + h->ip + "): no answer on " + h->ports[0] + (h->ports[1] ? String("/") + h->ports[1] : String()) + (wol::waking(i) ? " (wake in progress)" : ""));
        return;
    }
    if (!wol::count()) { reply(chat, "No machines yet. /addhost <name> <mac> [ip] [ports]"); return; }
    if (s_job.active) { reply(chat, "Already checking; the answer is coming."); return; }
    s_job.active = true;
    s_job.sim = s_sim;
    s_job.chat = chat;
    s_job.next = 0;
    s_job.text = String();
}

static void cmdAutowake(long long chat, char* arg) {
    char* who = strtok(arg, " ");
    char* onoff = strtok(nullptr, " ");
    char* mins = strtok(nullptr, " ");
    if (!who || !onoff || (strcasecmp(onoff, "on") && strcasecmp(onoff, "off"))) {
        String s = "Auto-wake (wake a machine that has been unreachable for N minutes):\n";
        for (int i = 0; i < wol::count(); i++) {
            const wol::Host* h = wol::host(i);
            s += String(h->name) + ": " + (h->autoWake ? String("on, ") + h->autoMin + " min" : String("off")) + "\n";
        }
        reply(chat, s + "Change: /autowake <machine|all> on|off [minutes]");
        return;
    }
    bool on = !strcasecmp(onoff, "on");
    int m = mins ? atoi(mins) : 0;
    if (!strcasecmp(who, "all")) {
        for (int i = 0; i < wol::count(); i++) wol::setAutoWake(i, on, m);
    } else {
        int i = hostArg(chat, who);
        if (i < 0) return;
        wol::setAutoWake(i, on, m);
    }
    logEvent("Auto-wake %s %s", who, on ? "on" : "off");
    char* none = (char*)"";
    cmdAutowake(chat, none);
}

static void cmdAddhost(long long chat, char* arg) {
    char* name = strtok(arg, " ");
    char* mac = strtok(nullptr, " ");
    char* ip = strtok(nullptr, " ");
    char* ports = strtok(nullptr, " ");
    char* bcast = strtok(nullptr, " ");
    wol::Host h;
    char err[64];
    if (!name || !mac) { reply(chat, "Usage: /addhost <name> <mac> [ip|-] [ports e.g. 8006,22] [broadcast]"); return; }
    if (!wol::makeHost(name, mac, ip, ports, bcast, &h, err, sizeof(err))) { reply(chat, String("Not saved: ") + err); return; }
    int i = wol::put(h, err, sizeof(err));
    if (i < 0) { reply(chat, String("Not saved: ") + err); return; }
    logEvent("WoL host %s saved", h.name);
    reply(chat, String("Saved: ") + hostLine(i) + "\n/wake " + h.name + " · /status " + h.name);
}

static void cmdDelhost(long long chat, char* arg) {
    int i = hostArg(chat, arg);
    if (i < 0) return;
    String name = wol::host(i)->name;
    wol::remove(i);
    logEvent("WoL host %s removed", name.c_str());
    reply(chat, "Removed " + name + ".");
}

static void cmdSethost(long long chat, char* arg) {
    char* who = strtok(arg, " ");
    char* field = strtok(nullptr, " ");
    char* value = strtok(nullptr, " ");
    if (!who || !field || !value) { reply(chat, "Usage: /sethost <machine> ip|mac|ports|broadcast|name <value>"); return; }
    int i = hostArg(chat, who);
    if (i < 0) return;
    wol::Host h = *wol::host(i);
    char mac[18], ports[16], err[64];
    wol::formatMac(h.mac, mac, sizeof(mac));
    snprintf(ports, sizeof(ports), "%u,%u", h.ports[0], h.ports[1]);
    String name = h.name, ip = h.ip, bc = h.broadcast, m = mac, p = ports;
    if (!strcasecmp(field, "ip")) ip = value;
    else if (!strcasecmp(field, "mac")) m = value;
    else if (!strcasecmp(field, "ports")) p = value;
    else if (!strcasecmp(field, "broadcast")) bc = value;
    else if (!strcasecmp(field, "name")) name = value;
    else { reply(chat, "Field: ip, mac, ports, broadcast or name"); return; }
    wol::Host n;
    if (!wol::makeHost(name.c_str(), m.c_str(), ip.c_str(), p.c_str(), bc.c_str(), &n, err, sizeof(err))) {
        reply(chat, String("Not changed: ") + err);
        return;
    }
    wol::copySettings(h, &n);
    if (strcasecmp(n.name, h.name)) wol::remove(i);          // renamed: replace the entry
    int j = wol::put(n, err, sizeof(err));
    if (j < 0) { reply(chat, String("Not changed: ") + err); return; }
    reply(chat, "Updated: " + hostLine(j));
}

static void cmdWol(long long chat, char* arg) {
    if (!strcasecmp(arg, "on") || !strcasecmp(arg, "off")) {
        wol::setEnabled(!strcasecmp(arg, "on"));
        logEvent("WoL %s", wol::enabled() ? "on" : "off");
    }
    Buttons b;
    b.add(wol::enabled() ? "Turn off" : "Turn on", wol::enabled() ? "/wol off" : "/wol on");
    reply(chat, String("Wake-on-LAN is ") + (wol::enabled() ? "on" : "off") + " for all machines.", b.json());
}

static void cmdInfo(long long chat, char*) { runAndReply(chat, "status"); }

static void cmdLog(long long chat, char* arg) {
    int n = *arg ? atoi(arg) : 15;
    if (n <= 0 || n > LOG_LINES) n = LOG_LINES;
    int total = logCount();
    String s = "Event log (newest last):\n";
    for (int i = total > n ? total - n : 0; i < total; i++) { s += logLine(i); s += "\n"; }
    reply(chat, total ? s : String("Event log is empty."));
}

static void cmdPortal(long long chat, char* arg) {
    String line = "portal";
    if (*arg) line += String(" ") + arg;
    runConsole(chat, line);
}

static void cmdSet(long long chat, char* arg) {
    char* name = strtok(arg, " ");
    char* value = strtok(nullptr, " ");
    if (name && value) {
        bool on = !strcasecmp(value, "on");
        if (!on && strcasecmp(value, "off")) { reply(chat, "Use on or off."); return; }
        if (!strcasecmp(name, "autologin")) portal::setEnabled(on);
        else if (!strcasecmp(name, "wol")) wol::setEnabled(on);
        else if (!strcasecmp(name, "web")) settings::setWebPage(on);
        else if (!strcasecmp(name, "keyboard")) {
            settings::setKeyboard(on);
            reply(chat, "The keyboard change applies after /reboot.");
        } else if (!strcasecmp(name, "autoapprove")) {
            if (on) { runConsole(chat, "auto on"); return; }   // weakens protection: OK on the device
            settings::setAutoApprove(false);
        } else { reply(chat, "Unknown switch. /set lists them."); return; }
        logEvent("Remote: %s %s", name, on ? "on" : "off");
    }
    Buttons b;
    struct { const char* key; const char* label; bool on; } sw[] = {
        {"autologin", "Campus auto-login", portal::enabled()},
        {"wol", "Wake-on-LAN", wol::enabled()},
        {"autoapprove", "Auto-approve sign-ins", settings::autoApprove()},
        {"keyboard", "Bluetooth keyboard", settings::keyboard()},
        {"web", "Web page", settings::webPage()},
    };
    String s = "Switches (tap to flip):\n";
    for (auto& x : sw) {
        s += String(x.on ? "✅ " : "⬜ ") + x.label + " (" + x.key + ")\n";
        b.add(String(x.on ? "✅ " : "⬜ ") + x.label, String("/set ") + x.key + (x.on ? " off" : " on"), 1);
    }
    s += String("🔔 Notifications: ") + notifyLevelName(s_notifyLevel) + " (/notify)\n";
    s += String("🔢 TOTP codes over Telegram: ") + (s_remoteCodes ? "allowed" : "off") + " (only changeable on the device)";
    reply(chat, s, b.json());
}

static void cmdNotify(long long chat, char* arg) {
    if (!strcasecmp(arg, "off")) setNotifyLevel(0);
    else if (!strcasecmp(arg, "important")) setNotifyLevel(1);
    else if (!strcasecmp(arg, "all")) setNotifyLevel(2);
    Buttons b;
    b.add("Off", "/notify off", 3);
    b.add("Important", "/notify important", 3);
    b.add("All events", "/notify all", 3);
    reply(chat, String("Notifications: ") + notifyLevelName(s_notifyLevel) +
                ".\nImportant = boots, campus drops, sign-ins, PIN / pairing / backup changes.", b.json());
}

static uint32_t s_rebootAt = 0;
static void cmdReboot(long long chat, char*) {
    reply(chat, "Rebooting the AuthKey…");
    s_rebootAt = millis() | 1;
}

static void cmdHybrid(long long chat, char* arg) {
    if (strncasecmp(arg, "FIDO:/", 6)) { reply(chat, "Send the passkey QR's text: /hybrid FIDO:/…"); return; }
    runConsole(chat, String("hybrid ") + arg);
}

static void cmdTotp(long long chat, char*) {
    String s = "Authenticator accounts:\n";
    TotpAccount a;
    for (int i = 0; i < totp::count(); i++) if (totp::get(i, &a)) s += String(i + 1) + ". " + a.name + "\n";
    crypto::wipe(&a, sizeof(a));
    if (!totp::count()) s = "No authenticator accounts.";
    else s += s_remoteCodes ? "/code <number or name>" : "(codes stay on the device; allow in Menu → Remote)";
    reply(chat, s);
}

static void cmdCode(long long chat, char* arg) {
    if (!s_remoteCodes) {
        reply(chat, "Sending TOTP codes over Telegram is off. It can only be allowed on the AuthKey "
                    "(Menu → Remote), because whoever reads this chat would get your second factor.");
        return;
    }
    time_t now = network::now();
    if (!now) { reply(chat, "The AuthKey's clock isn't set yet."); return; }
    TotpAccount a;
    int found = -1;
    for (int i = 0; i < totp::count() && found < 0; i++) {
        if (!totp::get(i, &a)) continue;
        if (atoi(arg) == i + 1 || !strcasecmp(a.name, arg)) found = i;
    }
    if (found < 0) { crypto::wipe(&a, sizeof(a)); reply(chat, "No such account. /totp lists them."); return; }
    char code[16];
    totp::format(a, totp::generate(a, now), code, sizeof(code));
    String s = String(a.name) + ": " + code + " (" + totp::secondsRemaining(a, now) + " s left)";
    crypto::wipe(&a, sizeof(a));
    logEvent("TOTP code sent remotely");
    reply(chat, s);
    crypto::wipe(code, sizeof(code));
}

static void cmdCmd(long long chat, char* arg) {
    if (!*arg) { reply(chat, "Usage: /cmd <console command>, e.g. /cmd status, /cmd wifi list, /cmd help"); return; }
    runConsole(chat, arg);
}

// --- Machine screen: auto-wake, alerts, pause, maintenance --------------------------------

static String fmtWhen(time_t t) {
    if (!t) return "?";
    char b[20];
    struct tm lt;
    localtime_r(&t, &lt);
    strftime(b, sizeof(b), "%a %d %b %H:%M", &lt);
    return b;
}

static String fmtIn(long s) {
    if (s < 0) s = 0;
    if (s < 3600) return String(s / 60) + " min";
    if (s < 2 * 86400) return String(s / 3600) + " h " + (s % 3600 / 60) + " min";
    return String(s / 86400) + " d " + (s % 86400 / 3600) + " h";
}

static String windowsText(int i) {
    const wol::Host* h = wol::host(i);
    String s;
    char w[40];
    for (const wol::Window& win : h->maint) {
        if (!win.days) continue;
        wol::formatWindow(win, w, sizeof(w));
        if (s.length()) s += "; ";
        s += w;
    }
    return s;
}

static String pauseText(int i) {
    const wol::Host* h = wol::host(i);
    if (!wol::paused(i)) return String();
    if (h->pausedUntil == WOL_PAUSE_UNTIL_UP) return "until it is up again";
    return "until " + fmtWhen(h->pausedUntil);
}

static void showHost(long long chat, int i) {
    const wol::Host* h = wol::host(i);
    char mac[18];
    wol::formatMac(h->mac, mac, sizeof(mac));
    int st = wol::lastState(i);
    String s = String("🖥 ") + h->name + "  " +
               (wol::waking(i) ? "⏳ waking" : st > 0 ? "🟢 up" : st == 0 ? "🔴 down" : "⚪ not checked yet");
    time_t since = wol::stateSince(i), now = network::now();
    if (since && now && st >= 0) s += " for " + fmtIn(now - since);
    s += String("\n") + (h->ip[0] ? h->ip : "no IP") + " · " + mac + " · ports " + h->ports[0] +
         (h->ports[1] ? String(",") + h->ports[1] : String()) + "\n\n";
    s += String("⏰ Auto-wake: ") + (h->autoWake ? String("on, after ") + h->autoMin + " min unreachable" : String("off")) + "\n";
    s += String("🔔 Alerts (down / back up): ") + (h->alerts ? "on" : "off") + "\n";
    String p = pauseText(i);
    if (p.length()) s += "⏸ Paused " + p + "\n";
    String w = windowsText(i);
    if (w.length()) {
        s += "🛠 Maintenance: " + w +
             (h->maintWake ? String(" (wakes it ") + WOL_MAINT_PREWAKE_MIN + " min before)" : String(" (no wake before)")) + "\n";
        time_t next = wol::nextWindow(i);
        if (wol::inMaintenance(i)) s += "   ➜ in a window right now\n";
        else if (next && now) s += "   ➜ next: " + fmtWhen(next) + " (in " + fmtIn(next - now) + ")\n";
    } else {
        s += String("🛠 Maintenance: none (/maint ") + h->name + " add sat 00:00 120)\n";
    }
    if (!wol::enabled()) s += "\n⚠️ Wake-on-LAN is off for all machines (/wol on).";

    String n = h->name;
    Buttons b;
    b.add("⏰ Wake", "/wake " + n);
    b.add("🔎 Check", "/status " + n);
    b.add(h->autoWake ? "✅ Auto-wake on" : "⬜ Auto-wake off", "/host " + n + (h->autoWake ? " auto off" : " auto on"), 1);
    b.newRow();
    for (int m : {5, 10, 30, 60})
        b.add(String(h->autoWake && h->autoMin == m ? "• " : "") + m + " min", "/host " + n + " delay " + m, 4);
    b.newRow();
    b.add(h->alerts ? "🔔 Alerts on" : "🔕 Alerts off", "/host " + n + (h->alerts ? " alerts off" : " alerts on"));
    if (wol::paused(i)) b.add("▶️ Resume", "/host " + n + " resume");
    else b.add("⏸ Pause 2 h", "/host " + n + " pause 2h");
    if (w.length())
        b.add(h->maintWake ? "✅ Wake before maintenance" : "⬜ Wake before maintenance",
              "/host " + n + (h->maintWake ? " maintwake off" : " maintwake on"), 1);
    b.newRow();
    if (proxmox::forHost(i) >= 0) b.add("📊 Proxmox", "/pve " + n);
    b.add("🔄 Refresh", "/host " + n);
    b.add("« Machines", "/hosts");
    view(chat, s, b.json());
}

// /host <machine> [auto on|off | delay <min> | alerts on|off | pause <2h> | resume | maintwake on|off]
static void cmdHost(long long chat, char* arg) {
    char* who = strtok(arg, " ");
    char* what = strtok(nullptr, " ");
    char* value = strtok(nullptr, " ");
    if (!who) {
        char none[1] = "";
        cmdHosts(chat, none);
        return;
    }
    int i = hostArg(chat, who);
    if (i < 0) return;
    const wol::Host* h = wol::host(i);
    if (what) {
        bool on = value && !strcasecmp(value, "on");
        if (!strcasecmp(what, "auto") && value) wol::setAutoWake(i, on);
        else if (!strcasecmp(what, "delay") && value && atoi(value) > 0) wol::setAutoWake(i, true, atoi(value));
        else if (!strcasecmp(what, "alerts") && value) wol::setAlerts(i, on);
        else if (!strcasecmp(what, "maintwake") && value) wol::setMaintWake(i, on);
        else if (!strcasecmp(what, "resume")) wol::pause(i, 0);
        else if (!strcasecmp(what, "pause")) {
            uint32_t secs = value && !strcasecmp(value, "up") ? WOL_PAUSE_UNTIL_UP : wol::parseDuration(value ? value : "2h");
            if (!secs || !wol::pause(i, secs)) { reply(chat, "Pause for how long? e.g. 2h, 30m, 1d (the clock must be set)."); return; }
        } else {
            reply(chat, "Usage: /host <machine> [auto on|off | delay <min> | alerts on|off | pause <2h|up> | resume | maintwake on|off]");
            return;
        }
        logEvent("Remote: %s %s %s", h->name, what, value ? value : "");
    }
    showHost(chat, i);
}

static void forHosts(long long chat, const char* who, void (*fn)(int)) {
    if (!strcasecmp(who, "all")) { for (int i = 0; i < wol::count(); i++) fn(i); return; }
    int i = hostArg(chat, who);
    if (i >= 0) fn(i);
}

static uint32_t s_pauseSecs;
static bool     s_alertsOn;

// /pause <machine|all> [2h|30m|1d|up|off]
static void cmdPause(long long chat, char* arg) {
    char* who = strtok(arg, " ");
    char* len = strtok(nullptr, " ");
    if (!who) {
        String s = "Pause auto-wake and alerts for a machine (maintenance, tinkering):\n";
        for (int i = 0; i < wol::count(); i++) {
            String p = pauseText(i);
            s += String(wol::host(i)->name) + ": " + (p.length() ? "paused " + p : String("not paused")) + "\n";
        }
        reply(chat, s + "/pause <machine|all> 2h · 30m · 1d · up (until it is up again) · off");
        return;
    }
    s_pauseSecs = !len ? 7200 : !strcasecmp(len, "off") ? 0 : !strcasecmp(len, "up") ? WOL_PAUSE_UNTIL_UP : wol::parseDuration(len);
    if (len && strcasecmp(len, "off") && !s_pauseSecs) { reply(chat, "Length like 2h, 30m, 1d, up or off."); return; }
    if (s_pauseSecs && s_pauseSecs != WOL_PAUSE_UNTIL_UP && !network::now()) {
        reply(chat, "The AuthKey's clock isn't set yet; use /pause <machine> up.");
        return;
    }
    forHosts(chat, who, [](int i) { wol::pause(i, s_pauseSecs); });
    logEvent("Remote: pause %s %s", who, len ? len : "2h");
    String s;
    for (int i = 0; i < wol::count(); i++) {
        String p = pauseText(i);
        s += String(wol::host(i)->name) + ": " + (p.length() ? "⏸ paused " + p : String("▶️ active")) + "\n";
    }
    reply(chat, s);
}

// /alerts <machine|all> on|off
static void cmdAlerts(long long chat, char* arg) {
    char* who = strtok(arg, " ");
    char* onoff = strtok(nullptr, " ");
    if (who && onoff && (!strcasecmp(onoff, "on") || !strcasecmp(onoff, "off"))) {
        s_alertsOn = !strcasecmp(onoff, "on");
        forHosts(chat, who, [](int i) { wol::setAlerts(i, s_alertsOn); });
        logEvent("Remote: alerts %s %s", who, onoff);
    }
    String s = "Down / back-up alerts (\"down\" = 2 missed checks in a row, about 2 min):\n";
    for (int i = 0; i < wol::count(); i++) s += String(wol::host(i)->name) + ": " + (wol::host(i)->alerts ? "on" : "off") + "\n";
    s += String("Notifications: ") + notifyLevelName(s_notifyLevel) + (s_notifyLevel ? "" : " (alerts muted: /notify important)");
    reply(chat, s + "\n/alerts <machine|all> on|off");
}

// /maint [<machine> add <days> <HH:MM> <min> | clear | wake on|off]
static void cmdMaint(long long chat, char* arg) {
    char* who = strtok(arg, " ");
    char* what = strtok(nullptr, " ");
    char* rest = strtok(nullptr, "");
    if (who && what) {
        int i = hostArg(chat, who);
        if (i < 0) return;
        char err[64];
        wol::Window w;
        if (!strcasecmp(what, "add")) {
            if (!wol::parseWindow(rest, &w, err, sizeof(err)) || !wol::addWindow(i, w, err, sizeof(err))) {
                reply(chat, String("Not added: ") + err);
                return;
            }
        } else if (!strcasecmp(what, "clear")) {
            wol::clearWindows(i);
        } else if (!strcasecmp(what, "wake") && rest) {
            wol::setMaintWake(i, !strncasecmp(rest, "on", 2));
        } else {
            reply(chat, "Usage: /maint <machine> add <days> <HH:MM> <minutes> | clear | wake on|off");
            return;
        }
        logEvent("Remote: maint %s %s", wol::host(i)->name, what);
        showHost(chat, i);
        return;
    }
    String s = "Maintenance windows (weekly, local time). The AuthKey wakes the machine a few minutes "
               "before if it is off, keeps quiet about restarts inside the window and reports when it ends";
    s += proxmox::count() ? " (with Proxmox: backups, updates, restarts).\n\n" : ".\n\n";
    for (int i = 0; i < wol::count(); i++) {
        String w = windowsText(i);
        s += String(wol::host(i)->name) + ": " + (w.length() ? w : String("none")) + "\n";
    }
    s += "\n/maint <machine> add sat 00:00 120\n/maint <machine> add sun 00:00 2h\n/maint <machine> clear · wake on|off\n"
         "Days: sun..sat, sat,sun, mon-fri, daily, weekend.";
    reply(chat, s);
}

// --- Proxmox -------------------------------------------------------------------------------

// Two-step confirmation for power actions: the button carries a short code
// that is valid for 2 minutes and for that one action.
static struct { uint16_t code; uint32_t untilMs; String what; } s_confirm;

static String confirmCode(const String& what) {
    s_confirm.code = 1000 + esp_random() % 9000;
    s_confirm.untilMs = millis() + 120000;
    s_confirm.what = what;
    return String(s_confirm.code);
}

static bool confirmed(const String& what, const char* code) {
    bool ok = code && s_confirm.code && atoi(code) == s_confirm.code && s_confirm.what == what &&
              (int32_t)(millis() - s_confirm.untilMs) < 0;
    if (ok) s_confirm.code = 0;
    return ok;
}

static bool pveBusy(long long chat) {
    if (ctap::busy() || hybrid::state() != hybrid::State::Idle) {
        reply(chat, "The AuthKey is busy with a sign-in; try again in a moment.");
        return true;
    }
    return false;
}

// Config index from the first word if it names a Proxmox machine, else the first server.
static int pveArg(long long chat, char** words, int* n) {
    if (!proxmox::count()) {
        reply(chat, "No Proxmox server set up. Add PROXMOX_TOKEN_ID and PROXMOX_TOKEN to .env and flash (README: Proxmox).");
        return -1;
    }
    if (*n && !isdigit((unsigned char)words[0][0])) {
        static const char* const VERBS[] = {"shutdown", "reboot", "cert", "unpin"};
        for (const char* v : VERBS) if (!strcasecmp(words[0], v)) return 0;
        int c = proxmox::find(words[0]);
        if (c < 0) { reply(chat, String("No Proxmox server \"") + words[0] + "\"."); return -1; }
        for (int k = 1; k < *n; k++) words[k - 1] = words[k];
        (*n)--;
        return c;
    }
    return 0;
}

// /pve [machine] [shutdown|reboot [code] | unpin | cert]
static void cmdPve(long long chat, char* arg) {
    char* words[4];
    int n = 0;
    for (char* t = strtok(arg, " "); t && n < 4; t = strtok(nullptr, " ")) words[n++] = t;
    int c = pveArg(chat, words, &n);
    if (c < 0) return;
    String m = proxmox::machine(c);
    int host = wol::find(m.c_str());
    const char* what = n ? words[0] : "";
    if (!strcasecmp(what, "cert")) { reply(chat, m + " certificate: " + proxmox::pinInfo(c)); return; }
    if (!strcasecmp(what, "unpin")) { runConsole(chat, "pve unpin " + m); return; }
    if (!strcasecmp(what, "shutdown") || !strcasecmp(what, "reboot")) {
        bool off = !strcasecmp(what, "shutdown");
        String action = String(off ? "shutdown " : "reboot ") + m;
        if (!confirmed(action, n > 1 ? words[1] : nullptr)) {
            Buttons b;
            b.add(String(off ? "⏻ Yes, shut down " : "🔁 Yes, reboot ") + m,
                  "/pve " + m + (off ? " shutdown " : " reboot ") + confirmCode(action), 1);
            b.add("Cancel", "/pve " + m, 1);
            reply(chat,
                  off ? "Shut down " + m + "? Its running VMs and containers are shut down first. "
                        "Auto-wake stays paused until you wake it again."
                      : "Reboot " + m + "? Running guests restart with it.",
                  b.json());
            return;
        }
        if (pveBusy(chat)) return;
        String out;
        bool ok = proxmox::nodePower(c, off ? "shutdown" : "reboot", out);
        if (ok && host >= 0) {
            if (off) {
                wol::expectShutdown(host, "shut down from Telegram");
                out += "\nI'll tell you when it is off. Auto-wake and alerts are paused until it is up again (/wake " + m + ").";
            } else {
                wol::expectRestart(host);
                out += "\nI'll tell you when it is back.";
            }
        }
        reply(chat, out);
        return;
    }
    if (*what) { reply(chat, "Usage: /pve [machine] [shutdown | reboot | cert | unpin]"); return; }
    if (pveBusy(chat)) return;
    String out;
    proxmox::summary(c, out);
    if (!out.endsWith("\n")) out += "\n";
    if (host >= 0) {
        time_t next = wol::nextWindow(host), now = network::now();
        if (next && now) out += "🛠 Next maintenance: " + fmtWhen(next) + " (in " + fmtIn(next - now) + ")\n";
    }
    Buttons b;
    b.add("🔄 Refresh", "/pve " + m);
    b.add("🧩 Guests", "/vm " + m);
    b.add("⏻ Shut down", "/pve " + m + " shutdown");
    b.add("🔁 Reboot", "/pve " + m + " reboot");
    if (host >= 0) b.add(String("🖥 ") + m + " settings", "/host " + m, 1);
    view(chat, out, b.json());
}

// /vm [machine] [<vmid> [start|shutdown|reboot|stop [code]]]
static void cmdVm(long long chat, char* arg) {
    char* words[5];
    int n = 0;
    for (char* t = strtok(arg, " "); t && n < 5; t = strtok(nullptr, " ")) words[n++] = t;
    int c = pveArg(chat, words, &n);
    if (c < 0) return;
    String m = proxmox::machine(c);
    int vmid = n ? atoi(words[0]) : 0;
    const char* action = n > 1 ? words[1] : "";
    if (*action) {
        bool known = !strcasecmp(action, "start") || !strcasecmp(action, "shutdown") || !strcasecmp(action, "reboot") ||
                     !strcasecmp(action, "stop");
        if (!known) { reply(chat, "Action: start, shutdown, reboot or stop"); return; }
        String key = String(action) + " " + m + " " + vmid;
        if (strcasecmp(action, "start") && !confirmed(key, n > 2 ? words[2] : nullptr)) {
            Buttons b;
            b.add(String("Yes, ") + action + " " + vmid, "/vm " + m + " " + vmid + " " + action + " " + confirmCode(key), 1);
            b.add("Cancel", "/vm " + m + " " + vmid, 1);
            reply(chat, String(action) + " guest " + vmid + " on " + m + "?" +
                        (!strcasecmp(action, "stop") ? " Stop is a hard power-off (like pulling the plug)." : ""),
                  b.json());
            return;
        }
        if (pveBusy(chat)) return;
        String out;
        proxmox::guestPower(c, vmid, action, out);
        reply(chat, out);
        return;
    }
    if (pveBusy(chat)) return;
    static proxmox::Guest g[24];   // static: the loop stack is small
    int count = 0;
    String err;
    if (!proxmox::guests(c, g, 24, &count, err) && !count) { reply(chat, "❌ " + err); return; }
    if (!n) {
        String s = String("Guests on ") + m + ":\n";
        Buttons b;
        for (int i = 0; i < count; i++) {
            s += String(g[i].running ? "🟢 " : "⚪ ") + g[i].vmid + " " + g[i].name + (g[i].lxc ? " (CT)" : "") + "\n";
            b.add(String(g[i].running ? "🟢 " : "⚪ ") + g[i].vmid + " " + g[i].name, "/vm " + m + " " + g[i].vmid);
        }
        if (!count) s += "(none)\n";
        s += err;
        b.add("🔄 Refresh", "/vm " + m);
        b.add("📊 " + m, "/pve " + m);
        view(chat, s, b.json());
        return;
    }
    const proxmox::Guest* found = nullptr;
    for (int i = 0; i < count; i++) if (g[i].vmid == vmid) found = &g[i];
    if (!found) { reply(chat, String("No guest ") + vmid + " on " + m + ". /vm lists them."); return; }
    String base = "/vm " + m + " " + vmid + " ";
    Buttons b;
    if (found->running) {
        b.add("⏻ Shut down", base + "shutdown");
        b.add("🔁 Reboot", base + "reboot");
        b.add("⛔ Stop (hard)", base + "stop");
    } else {
        b.add("▶️ Start", base + "start");
    }
    b.add("« Guests", "/vm " + m);
    view(chat, String(found->running ? "🟢 " : "⚪ ") + vmid + " " + found->name + (found->lxc ? " (container)" : " (VM)") +
                   " on " + m + ": " + (found->running ? "running" : "stopped"),
         b.json());
}

const Command COMMANDS[] = {
    {"menu",     "",                                   "buttons for everything", cmdMenu},
    {"wake",     "[machine|all]",                      "wake-on-LAN, then report when it's up", cmdWake},
    {"status",   "[machine|all]",                      "🟢 up / 🔴 down", cmdStatus},
    {"hosts",    "",                                   "machines and their last state", cmdHosts},
    {"host",     "<machine> [setting value]",          "one machine: auto-wake, alerts, pause, maintenance", cmdHost},
    {"pause",    "<machine|all> [2h|30m|up|off]",      "pause auto-wake and alerts", cmdPause},
    {"alerts",   "<machine|all> on|off",               "down / back-up alerts", cmdAlerts},
    {"maint",    "[<machine> add sat 00:00 120|clear]", "weekly maintenance windows", cmdMaint},
    {"pve",      "[machine] [shutdown|reboot]",        "Proxmox status, backups, updates, power", cmdPve},
    {"vm",       "[machine] [<id> start|shutdown|…]",  "Proxmox VMs and containers", cmdVm},
    {"autowake", "<machine|all> on|off [min]",         "wake it when unreachable that long", cmdAutowake},
    {"addhost",  "<name> <mac> [ip] [ports] [bcast]",  "add or replace a machine", cmdAddhost},
    {"sethost",  "<machine> ip|mac|ports|broadcast|name <value>", "change a machine", cmdSethost},
    {"delhost",  "<machine>",                          "remove a machine", cmdDelhost},
    {"wol",      "[on|off]",                           "wake-on-LAN for all machines", cmdWol},
    {"info",     "",                                   "AuthKey status (WiFi, campus, Bluetooth, RAM…)", cmdInfo},
    {"log",      "[lines]",                            "event log", cmdLog},
    {"portal",   "[login|logout|on|off]",              "campus internet login", cmdPortal},
    {"set",      "[switch on|off]",                    "feature switches", cmdSet},
    {"notify",   "[off|important|all]",                "event notifications", cmdNotify},
    {"totp",     "",                                   "authenticator account names", cmdTotp},
    {"code",     "<account>",                          "a TOTP code (only if allowed on the device)", cmdCode},
    {"hybrid",   "<FIDO:/…>",                          "passkey sign-in from a QR's text (needs OK)", cmdHybrid},
    {"cmd",      "<console command>",                  "run any console command", cmdCmd},
    {"reboot",   "",                                   "restart the AuthKey", cmdReboot},
    {"help",     "",                                   "this list", cmdHelp},
};
const int COMMAND_COUNT = sizeof(COMMANDS) / sizeof(COMMANDS[0]);

static void dispatch(long long chat, const char* textIn) {
    static char text[360];
    strlcpy(text, textIn, sizeof(text));
    if (text[0] != '/') { reply(chat, "Commands start with /. Try /menu or /help."); return; }
    char* arg = strchr(text, ' ');
    if (arg) { *arg++ = '\0'; while (*arg == ' ') arg++; }
    else arg = text + strlen(text);
    char* at = strchr(text, '@');               // "/wake@MyBot" in group chats
    if (at) *at = '\0';
    if (!strcasecmp(text, "/start")) { cmdMenu(chat, arg); return; }
    for (int i = 0; i < COMMAND_COUNT; i++) {
        if (!strcasecmp(text + 1, COMMANDS[i].name)) {
            logf("TG", "/%s from %lld", COMMANDS[i].name, chat);
            COMMANDS[i].fn(chat, arg);
            return;
        }
    }
    reply(chat, "Unknown command. /menu or /help.");
}

void simulate(const char* text) {
    s_sim = true;
    dispatch(s_chatCount ? s_chats[0] : 0, text);
    s_sim = false;
}

// --- Event notifications --------------------------------------------------------------------

static uint32_t s_seenSeq = 0;
static uint32_t s_nextNotifyMs = 0;

static bool startsWith(const char* s, const char* p) { return !strncmp(s, p, strlen(p)); }

static bool forwardable(const char* msg, int level) {
    // Already reported directly, or about the bot itself.
    if (startsWith(msg, "TG ") || startsWith(msg, "WoL ") || strstr(msg, "after WoL") || startsWith(msg, "Remote:") ||
        startsWith(msg, "Server ") || startsWith(msg, "PVE ") || strstr(msg, "maintenance"))
        return false;
    if (level >= 2) return true;
    static const char* const IMPORTANT[] = {
        "Boot", "IITG", "PIN", "Device PIN", "Backup", "Passkey", "FIDO reset", "Paired PC", "PC pairing",
        "Web access", "BLE paired", "BT keyboard", "Auto-approve", "Signed in", "Registered", "Denied",
        "TOTP code sent",
    };
    for (const char* p : IMPORTANT) if (startsWith(msg, p)) return true;
    return false;
}

static void forwardEvents() {
    uint32_t total = logTotal();
    if (s_seenSeq >= total || (int32_t)(millis() - s_nextNotifyMs) < 0) return;
    String text;
    for (uint32_t q = s_seenSeq; q < total; q++) {
        const char* line = logLineBySeq(q);
        const char* msg = strchr(line, ' ');
        msg = msg ? msg + 1 : line;
        if (*line && s_notifyLevel && forwardable(msg, s_notifyLevel)) { text += line; text += "\n"; }
    }
    s_seenSeq = total;
    if (text.length()) {
        notify(("🔔 " + text).c_str());
        s_nextNotifyMs = millis() + 10000;    // batch bursts into one message
    }
}

// End of a maintenance window: add what Proxmox says (backups, updates, restarts).
static bool onMaintEnd(int host, const char* summary, time_t start) {
    int c = proxmox::forHost(host);
    if (c < 0 || wol::lastState(host) != 1) return false;
    String rep;
    proxmox::maintenanceReport(c, start, rep);
    alertNotify((String(summary) + "\n\n" + rep).c_str());
    return true;
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
    s_prefs.begin("tg", false);
    s_notifyLevel = s_prefs.getInt("notify", 1);
    s_remoteCodes = s_prefs.getBool("codes", false);
    s_seenSeq = logTotal();      // notify about events from now on (incl. this boot's)
    if (!enabled()) {
        logf("TG", "no TELEGRAM_BOT_TOKEN in .env: bot off (tg sim <command> still works)");
        return;
    }
    s_state = St::Idle;
    wol::setNotifier(notify);
    wol::setAlertNotifier(alertNotify);
    wol::setMaintEndHandler(onMaintEnd);
    backup::setReminder(alertNotify);
    if (finderMode())
        logf("TG", "no TELEGRAM_CHAT_ID yet: send your bot any message, its chat ID is logged here");
    else
        logf("TG", "bot on, %d allowed chat(s), notifications %s", s_chatCount, notifyLevelName(s_notifyLevel));
}

// --- Updates ------------------------------------------------------------------------------

static void handleUpdate(JsonObject u) {
    long long id = u["update_id"].as<long long>();
    if (id >= s_offset) s_offset = id + 1;

    // Button press: answer it (stops the spinner), then run its command.
    JsonObject cq = u["callback_query"];
    if (!cq.isNull()) {
        push(Out::Answer, 0, String(), String((const char*)(cq["id"] | "")));
        long long chat = cq["message"]["chat"]["id"].as<long long>();
        const char* data = cq["data"] | "";
        if (!allowed(chat)) {
            s_lastIgnored = chat;
            logf("TG", "ignored button from chat %lld", chat);
            return;
        }
        s_editMsg = cq["message"]["message_id"] | 0L;
        dispatch(chat, data);
        s_editMsg = 0;
        return;
    }

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
    dispatch(chat, text);
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
    char req[300];
    snprintf(req, sizeof(req),
             "GET /bot%s/getUpdates?offset=%lld&limit=1&timeout=%d"
             "&allowed_updates=%%5B%%22message%%22,%%22callback_query%%22%%5D HTTP/1.1\r\n"
             "Host: " TG_HOST "\r\nConnection: keep-alive\r\n\r\n",
             SECRET_TG_TOKEN, s_offset, TG_LONG_POLL_SECS);
    s_tls.print(req);
    memset(req, 0, sizeof(req));            // held the token
    s_respLen = 0;
    s_reqMs = millis();
    s_state = St::Polling;
}

static void sendRequest(const Outgoing& o) {
    const char* method;
    String body;
    if (o.type == Out::Answer) {
        method = "answerCallbackQuery";
        JsonDocument doc;
        doc["callback_query_id"] = o.extra;
        serializeJson(doc, body);
    } else if (o.type == Out::Edit) {
        method = "editMessageText";
        JsonDocument doc;
        doc["chat_id"] = o.chat;
        doc["message_id"] = o.msgId;
        doc["text"] = o.text;
        doc["disable_web_page_preview"] = true;
        if (o.extra.length()) doc["reply_markup"] = serialized(o.extra);
        serializeJson(doc, body);
    } else if (o.type == Out::Commands) {
        method = "setMyCommands";
        body = o.text;
    } else {
        method = "sendMessage";
        JsonDocument doc;
        doc["chat_id"] = o.chat;
        doc["text"] = o.text;
        doc["disable_web_page_preview"] = true;
        if (o.extra.length()) doc["reply_markup"] = serialized(o.extra);
        serializeJson(doc, body);
    }
    char head[220];
    snprintf(head, sizeof(head),
             "POST /bot%s/%s HTTP/1.1\r\nHost: " TG_HOST "\r\nConnection: keep-alive\r\n"
             "Content-Type: application/json\r\nContent-Length: %u\r\n\r\n",
             SECRET_TG_TOKEN, method, (unsigned)body.length());
    s_tls.print(head);
    s_tls.print(body);
    memset(head, 0, sizeof(head));
    s_respLen = 0;
    s_reqMs = millis();
    s_state = St::Sending;
}

// The command list Telegram shows when you type "/".
static void queueCommandList() {
    JsonDocument doc;
    JsonArray list = doc["commands"].to<JsonArray>();
    for (int i = 0; i < COMMAND_COUNT; i++) {
        JsonObject c = list.add<JsonObject>();
        c["command"] = COMMANDS[i].name;
        c["description"] = COMMANDS[i].help;
    }
    String body;
    serializeJson(doc, body);
    push(Out::Commands, 0, body, String());
    s_commandsSet = true;
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
    if (!s_commandsSet && !finderMode()) queueCommandList();
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
    stepStatusJob();                        // local work, also without a token (tg sim)
    if (s_state == St::Off) return;
    forwardEvents();
    if (s_rebootAt && (!s_outCount || millis() - s_rebootAt > 15000)) {
        logFlush();
        delay(200);
        ESP.restart();
    }
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
            // Something is waiting to go out: abandon the long poll (updates
            // stay queued at Telegram until confirmed by the next offset).
            else if (s_state == St::Polling && s_outCount && !s_respLen) hangUp();
            return;
        }
        if (s_state == St::Polling) {
            handlePoll(status, body, len);
        } else {
            // 400 on an edit is usually "message is not modified": harmless.
            if (status != 200 && !(status == 400 && s_out[s_outHead].type == Out::Edit))
                setError("%s HTTP %d", s_out[s_outHead].type == Out::Message ? "sendMessage" : "request", status);
            s_out[s_outHead].text = String();       // sent (or rejected: don't retry forever)
            s_out[s_outHead].extra = String();
            s_outHead = (s_outHead + 1) % OUTBOX;
            s_outCount--;
        }
        s_respLen = 0;
        if (s_state == St::Polling || s_state == St::Sending) s_state = St::Idle;
        if (!keep) hangUp();
        return;
    }

    // Idle: connect if needed, then send what is queued or start a poll.
    if ((int32_t)(millis() - s_nextTryMs) < 0) return;
    if (!s_connected) {
        if (ctap::busy()) return;            // the handshake would stall a passkey prompt
        if (!connectTls()) { backOff(); return; }
    }
    if (s_outCount) sendRequest(s_out[s_outHead]);
    else sendPoll();
}

}  // namespace telegram
