#include "unlock/unlock.h"
#include "config.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "util/codec.h"

#include <ESPmDNS.h>
#include <Preferences.h>
#include <WiFi.h>

namespace unlock {

struct PcEntry {
    uint8_t id[UNLOCK_PC_ID_LEN];
    uint8_t key[UNLOCK_KEY_LEN];
    char    name[24];
};

static Preferences s_prefs;
static PcEntry     s_pcs[UNLOCK_MAX_PCS];
static bool        s_used[UNLOCK_MAX_PCS];

// One request may wait for the user at a time.
static Prompt   s_prompt = {PromptKind::None, "", "", 0};
static ReplyFn  s_reply = nullptr;
static void*    s_ctx = nullptr;
static int      s_slot = -1;
static uint8_t  s_challenge[UNLOCK_CHAL_LEN];
static PcEntry  s_pairing;

static WiFiServer s_server(UNLOCK_TCP_PORT);
static bool       s_serverUp = false;
static WiFiClient s_client;
static char       s_line[160];
static size_t     s_lineLen = 0;
static uint32_t   s_clientSince = 0;

static void slotKey(int i, char* key) { snprintf(key, 16, "pc%d", i); }

void init() {
    s_prefs.begin("unlock", false);
    for (int i = 0; i < UNLOCK_MAX_PCS; i++) {
        char key[16];
        slotKey(i, key);
        s_used[i] = s_prefs.isKey(key) && s_prefs.getBytes(key, &s_pcs[i], sizeof(PcEntry)) == sizeof(PcEntry);
    }
    logf("UNLOCK", "%d paired PC(s)", count());
}

static int find(const uint8_t pcId[UNLOCK_PC_ID_LEN]) {
    for (int i = 0; i < UNLOCK_MAX_PCS; i++) {
        if (s_used[i] && crypto::equal(s_pcs[i].id, pcId, UNLOCK_PC_ID_LEN)) return i;
    }
    return -1;
}

static void answer(int slot, const uint8_t* challenge, uint8_t mac[32]) {
    static const char label[] = "AuthKey unlock v1";
    crypto::hmacSha256Multi(s_pcs[slot].key, UNLOCK_KEY_LEN, (const uint8_t*)label, sizeof(label) - 1,
                            s_pcs[slot].id, UNLOCK_PC_ID_LEN, challenge, UNLOCK_CHAL_LEN, mac);
}

static void finish(bool ok) {
    ReplyFn reply = s_reply;
    void* ctx = s_ctx;
    uint8_t mac[32];
    bool isUnlock = s_prompt.kind == PromptKind::Unlock;
    if (ok && isUnlock) answer(s_slot, s_challenge, mac);
    if (ok && s_prompt.kind == PromptKind::Pair) {
        // Replace an existing entry for the same PC, else use a free slot.
        int slot = find(s_pairing.id);
        for (int i = 0; i < UNLOCK_MAX_PCS && slot < 0; i++) if (!s_used[i]) slot = i;
        if (slot < 0) {
            ok = false;
            logEvent("PC pairing: no free slot");
        } else {
            char key[16];
            slotKey(slot, key);
            s_pcs[slot] = s_pairing;
            s_used[slot] = s_prefs.putBytes(key, &s_pairing, sizeof(PcEntry)) == sizeof(PcEntry);
            ok = s_used[slot];
            if (ok) logEvent("Paired PC %s", s_pairing.name);
        }
        crypto::wipe(&s_pairing, sizeof(s_pairing));
    }
    if (isUnlock) logEvent(ok ? "Unlocked PC %s" : "PC unlock denied %s", s_prompt.name);
    s_prompt.kind = PromptKind::None;
    s_reply = nullptr;
    if (reply) reply(ok, ok && isUnlock ? mac : nullptr, ctx);
    crypto::wipe(mac, sizeof(mac));
}

bool pair(const uint8_t pcId[UNLOCK_PC_ID_LEN], const uint8_t key[UNLOCK_KEY_LEN], const char* name,
          const char* via, ReplyFn reply, void* ctx) {
    if (s_prompt.kind != PromptKind::None) return false;
    memcpy(s_pairing.id, pcId, UNLOCK_PC_ID_LEN);
    memcpy(s_pairing.key, key, UNLOCK_KEY_LEN);
    strlcpy(s_pairing.name, name, sizeof(s_pairing.name));
    s_prompt.kind = PromptKind::Pair;
    strlcpy(s_prompt.name, name, sizeof(s_prompt.name));
    s_prompt.via = via;
    s_prompt.startedMs = millis();
    s_reply = reply;
    s_ctx = ctx;
    return true;
}

void respond(const uint8_t pcId[UNLOCK_PC_ID_LEN], const uint8_t* challenge, size_t len, const char* via,
             ReplyFn reply, void* ctx) {
    int slot = find(pcId);
    if (slot < 0 || len != UNLOCK_CHAL_LEN || s_prompt.kind != PromptKind::None) {
        reply(false, nullptr, ctx);
        return;
    }
    s_slot = slot;
    memcpy(s_challenge, challenge, UNLOCK_CHAL_LEN);
    s_prompt.kind = PromptKind::Unlock;
    strlcpy(s_prompt.name, s_pcs[slot].name, sizeof(s_prompt.name));
    s_prompt.via = via;
    s_prompt.startedMs = millis();
    s_reply = reply;
    s_ctx = ctx;
    if (settings::autoApprove()) finish(true);   // hands-free, like passkey sign-in
}

int count() {
    int n = 0;
    for (int i = 0; i < UNLOCK_MAX_PCS; i++) n += s_used[i];
    return n;
}

bool name(int index, char* out, size_t cap) {
    if (index < 0 || index >= UNLOCK_MAX_PCS || !s_used[index]) return false;
    strlcpy(out, s_pcs[index].name, cap);
    return true;
}

bool remove(int index) {
    if (index < 0 || index >= UNLOCK_MAX_PCS || !s_used[index]) return false;
    char key[16];
    slotKey(index, key);
    s_prefs.remove(key);
    s_used[index] = false;
    crypto::wipe(&s_pcs[index], sizeof(PcEntry));
    return true;
}

const Prompt* prompt() { return s_prompt.kind == PromptKind::None ? nullptr : &s_prompt; }
void userApprove() { if (s_prompt.kind != PromptKind::None) finish(true); }
void userDeny() { if (s_prompt.kind != PromptKind::None) finish(false); }

// --- WiFi transport: "unlock <pcid-hex> <challenge-hex>\n" -> "UNLOCK <hex>\n" ---

static void tcpReply(bool ok, const uint8_t* mac, void*) {
    if (!s_client.connected()) return;
    if (ok && mac) {
        char hex[65];
        hexEncode(mac, 32, hex);
        s_client.printf("UNLOCK %s\n", hex);
    } else {
        s_client.print("ERR denied\n");
    }
    s_client.stop();
}

static void handleTcpLine(char* line) {
    char* cmd = strtok(line, " ");
    char* id = strtok(nullptr, " ");
    char* chal = strtok(nullptr, " ");
    uint8_t pcId[UNLOCK_PC_ID_LEN], challenge[UNLOCK_CHAL_LEN];
    if (!cmd || strcmp(cmd, "unlock") || !id || !chal ||
        hexDecode(id, strlen(id), pcId, sizeof(pcId)) != UNLOCK_PC_ID_LEN ||
        hexDecode(chal, strlen(chal), challenge, sizeof(challenge)) != UNLOCK_CHAL_LEN) {
        s_client.print("ERR bad request\n");
        s_client.stop();
        return;
    }
    respond(pcId, challenge, UNLOCK_CHAL_LEN, "WiFi", tcpReply, nullptr);
}

void loop() {
    // Prompt timeout
    if (s_prompt.kind != PromptKind::None && millis() - s_prompt.startedMs > FIDO_USER_TIMEOUT_MS) {
        logEvent("PC prompt timed out");
        finish(false);
    }

    if (!WiFi.isConnected()) {
        if (s_serverUp) { s_server.end(); s_serverUp = false; }
        return;
    }
    if (!s_serverUp) {
        s_server.begin();
        s_server.setNoDelay(true);
        if (MDNS.begin("authkey-esp32")) MDNS.addService("authkey", "tcp", UNLOCK_TCP_PORT);
        s_serverUp = true;
        logf("UNLOCK", "listening on %s:%d (authkey-esp32.local)", WiFi.localIP().toString().c_str(),
             UNLOCK_TCP_PORT);
    }

    if (!s_client || !s_client.connected()) {
        WiFiClient c = s_server.available();
        if (c) {
            s_client = c;
            s_lineLen = 0;
            s_clientSince = millis();
        }
        return;
    }
    // Waiting for a user decision on this client's request: keep it open.
    if (s_prompt.kind != PromptKind::None && s_reply == tcpReply) return;
    if (millis() - s_clientSince > 5000) { s_client.stop(); return; }
    while (s_client.available()) {
        char c = (char)s_client.read();
        if (c == '\n' || c == '\r') {
            if (s_lineLen) {
                s_line[s_lineLen] = '\0';
                s_lineLen = 0;
                handleTcpLine(s_line);
                return;
            }
        } else if (s_lineLen < sizeof(s_line) - 1) {
            s_line[s_lineLen++] = c;
        }
    }
}

}  // namespace unlock
