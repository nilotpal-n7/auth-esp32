#include "fido/credentials.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include <Preferences.h>

namespace creds {

static Preferences s_prefs;
static bool        s_used[FIDO_MAX_RESIDENT];
static uint8_t     s_rpHashPrefix[FIDO_MAX_RESIDENT][4];   // fast lookup
static uint32_t    s_created[FIDO_MAX_RESIDENT];
static uint32_t    s_nextCreated = 1;

static void slotKey(int i, char* key) { snprintf(key, 16, "r%d", i); }

// Subkeys derived from the master key so the MAC key and the key-derivation
// key are independent.
static void subkey(const char* label, uint8_t out[32]) {
    crypto::hmacSha256(settings::masterKey(), 32, (const uint8_t*)label, strlen(label), out);
}

void init() {
    s_prefs.begin("rk", false);
    int n = 0;
    ResidentCredential c;
    for (int i = 0; i < FIDO_MAX_RESIDENT; i++) {
        char key[16];
        slotKey(i, key);
        s_used[i] = s_prefs.isKey(key) && s_prefs.getBytes(key, &c, sizeof(c)) == sizeof(c);
        if (s_used[i]) {
            memcpy(s_rpHashPrefix[i], c.rpIdHash, 4);
            s_created[i] = c.created;
            if (c.created >= s_nextCreated) s_nextCreated = c.created + 1;
            n++;
        }
    }
    logf("CRED", "%d discoverable credential(s)", n);
}

static void macFor(const uint8_t* idPrefix /* type||nonce, 17 bytes */,
                   const uint8_t rpIdHash[32], uint8_t mac[32]) {
    uint8_t k[32];
    subkey("credential-mac", k);
    crypto::hmacSha256Multi(k, 32, idPrefix, 17, rpIdHash, 32, nullptr, 0, mac);
    crypto::wipe(k, sizeof(k));
}

static bool privFor(const uint8_t nonce[16], const uint8_t rpIdHash[32], uint8_t priv[32]) {
    uint8_t k[32];
    subkey("credential-key", k);
    crypto::hmacSha256Multi(k, 32, nonce, 16, rpIdHash, 32, nullptr, 0, priv);
    crypto::wipe(k, sizeof(k));
    return crypto::p256ValidPrivate(priv);
}

bool create(const uint8_t rpIdHash[32], bool resident,
            uint8_t credId[CRED_ID_LEN], uint8_t pub[65], uint8_t priv[32]) {
    credId[0] = resident ? CRED_TYPE_RESIDENT : CRED_TYPE_PLAIN;
    for (int attempt = 0; attempt < 8; attempt++) {
        crypto::random(credId + 1, 16);
        if (!privFor(credId + 1, rpIdHash, priv)) continue;   // ~2^-32 chance
        if (!crypto::p256Public(priv, pub)) continue;
        uint8_t mac[32];
        macFor(credId, rpIdHash, mac);
        memcpy(credId + 17, mac, 16);
        return true;
    }
    return false;
}

bool derive(const uint8_t* credId, size_t len, const uint8_t rpIdHash[32], uint8_t priv[32]) {
    if (len != CRED_ID_LEN) return false;
    if (credId[0] != CRED_TYPE_PLAIN && credId[0] != CRED_TYPE_RESIDENT) return false;
    uint8_t mac[32];
    macFor(credId, rpIdHash, mac);
    if (!crypto::equal(mac, credId + 17, 16)) return false;
    return privFor(credId + 1, rpIdHash, priv);
}

// --- Resident store ----------------------------------------------------------

int residentCapacity() { return FIDO_MAX_RESIDENT; }

int residentCount() {
    int n = 0;
    for (int i = 0; i < FIDO_MAX_RESIDENT; i++) n += s_used[i];
    return n;
}

bool residentGet(int slot, ResidentCredential* out) {
    if (slot < 0 || slot >= FIDO_MAX_RESIDENT || !s_used[slot]) return false;
    char key[16];
    slotKey(slot, key);
    return s_prefs.getBytes(key, out, sizeof(*out)) == sizeof(*out);
}

bool residentPut(const ResidentCredential& in) {
    ResidentCredential c = in;
    int target = -1;
    // Same RP + same user handle replaces the old credential (WebAuthn §6.1.2).
    ResidentCredential existing;
    for (int i = 0; i < FIDO_MAX_RESIDENT && target < 0; i++) {
        if (!s_used[i] || memcmp(s_rpHashPrefix[i], c.rpIdHash, 4) != 0) continue;
        if (residentGet(i, &existing) && memcmp(existing.rpIdHash, c.rpIdHash, 32) == 0 &&
            existing.userIdLen == c.userIdLen &&
            memcmp(existing.userId, c.userId, c.userIdLen) == 0) {
            target = i;
        }
    }
    for (int i = 0; i < FIDO_MAX_RESIDENT && target < 0; i++) {
        if (!s_used[i]) target = i;
    }
    if (target < 0) return false;

    c.created = s_nextCreated++;
    char key[16];
    slotKey(target, key);
    if (s_prefs.putBytes(key, &c, sizeof(c)) != sizeof(c)) return false;
    s_used[target] = true;
    memcpy(s_rpHashPrefix[target], c.rpIdHash, 4);
    s_created[target] = c.created;
    return true;
}

int residentFind(const uint8_t rpIdHash[32], int* slots, int maxSlots) {
    int all[FIDO_MAX_RESIDENT];
    int n = 0;
    ResidentCredential c;
    for (int i = 0; i < FIDO_MAX_RESIDENT; i++) {
        if (!s_used[i] || memcmp(s_rpHashPrefix[i], rpIdHash, 4) != 0) continue;
        if (residentGet(i, &c) && memcmp(c.rpIdHash, rpIdHash, 32) == 0) all[n++] = i;
    }
    // Newest first, so the most recently registered accounts are kept and the
    // newest one is the default.
    for (int a = 1; a < n; a++) {
        for (int b = a; b > 0 && s_created[all[b]] > s_created[all[b - 1]]; b--) {
            int t = all[b]; all[b] = all[b - 1]; all[b - 1] = t;
        }
    }
    if (n > maxSlots) n = maxSlots;
    memcpy(slots, all, n * sizeof(int));
    return n;
}

bool residentDelete(int slot) {
    if (slot < 0 || slot >= FIDO_MAX_RESIDENT || !s_used[slot]) return false;
    char key[16];
    slotKey(slot, key);
    s_prefs.remove(key);
    s_used[slot] = false;
    return true;
}

void residentWipe() {
    s_prefs.clear();
    memset(s_used, 0, sizeof(s_used));
    s_nextCreated = 1;
}

}  // namespace creds
