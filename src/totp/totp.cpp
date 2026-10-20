#include "totp/totp.h"
#include "config.h"
#include "core/log.h"
#include "crypto/crypto.h"
#include "util/codec.h"
#include <Preferences.h>

namespace totp {

// Accounts are stored densely in slots "a0".."aN-1" with count "n"; removal
// shifts later slots down so the on-screen order is stable.
static Preferences s_prefs;
static int s_count = 0;

static void slotKey(int i, char* key) { snprintf(key, 16, "a%d", i); }

void init() {
    s_prefs.begin("totp", false);
    s_count = s_prefs.getInt("n", 0);
    if (s_count < 0 || s_count > TOTP_MAX_ACCOUNTS) s_count = 0;
    logf("TOTP", "%d account(s)", s_count);
}

int count() { return s_count; }

bool get(int index, TotpAccount* out) {
    if (index < 0 || index >= s_count) return false;
    char key[16];
    slotKey(index, key);
    return s_prefs.getBytes(key, out, sizeof(*out)) == sizeof(*out);
}

int add(const TotpAccount& a) {
    if (s_count >= TOTP_MAX_ACCOUNTS || a.secretLen == 0) return -1;
    char key[16];
    slotKey(s_count, key);
    if (s_prefs.putBytes(key, &a, sizeof(a)) != sizeof(a)) return -1;
    s_count++;
    s_prefs.putInt("n", s_count);
    return s_count - 1;
}

bool remove(int index) {
    if (index < 0 || index >= s_count) return false;
    TotpAccount a;
    char key[16];
    for (int i = index; i < s_count - 1; i++) {
        if (!get(i + 1, &a)) return false;
        slotKey(i, key);
        s_prefs.putBytes(key, &a, sizeof(a));
    }
    crypto::wipe(&a, sizeof(a));
    slotKey(s_count - 1, key);
    s_prefs.remove(key);
    s_count--;
    s_prefs.putInt("n", s_count);
    return true;
}

uint32_t generate(const TotpAccount& a, time_t now) {
    uint64_t counter = (uint64_t)now / (a.period ? a.period : 30);
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = (uint8_t)counter; counter >>= 8; }

    uint8_t mac[64];
    size_t n = crypto::hmacTotp(a.algo, a.secret, a.secretLen, msg, sizeof(msg), mac);
    uint8_t off = mac[n - 1] & 0x0F;
    uint32_t bin = ((uint32_t)(mac[off] & 0x7F) << 24) | ((uint32_t)mac[off + 1] << 16) |
                   ((uint32_t)mac[off + 2] << 8) | mac[off + 3];
    uint32_t mod = a.digits == 8 ? 100000000u : 1000000u;
    return bin % mod;
}

uint8_t secondsRemaining(const TotpAccount& a, time_t now) {
    uint8_t p = a.period ? a.period : 30;
    return p - (uint8_t)(now % p);
}

void format(const TotpAccount& a, uint32_t code, char* out, size_t cap) {
    if (a.digits == 8) snprintf(out, cap, "%04u %04u", (unsigned)(code / 10000), (unsigned)(code % 10000));
    else               snprintf(out, cap, "%03u %03u", (unsigned)(code / 1000), (unsigned)(code % 1000));
}

bool fromBase32(const char* name, const char* b32, TotpAccount* out) {
    memset(out, 0, sizeof(*out));
    int n = base32Decode(b32, out->secret, sizeof(out->secret));
    if (n <= 0) return false;
    out->secretLen = (uint8_t)n;
    strlcpy(out->name, name, sizeof(out->name));
    out->digits = 6;
    out->period = 30;
    out->algo = 1;
    return true;
}

static bool queryParam(const char* query, const char* key, char* out, size_t cap) {
    size_t klen = strlen(key);
    const char* p = query;
    while (p && *p) {
        if (strncasecmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            size_t i = 0;
            while (*p && *p != '&' && i + 1 < cap) out[i++] = *p++;
            out[i] = '\0';
            urlDecodeInPlace(out);
            return true;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return false;
}

bool parseUri(const char* uri, TotpAccount* out) {
    static const char prefix[] = "otpauth://totp/";
    if (strncasecmp(uri, prefix, sizeof(prefix) - 1) != 0) return false;
    const char* label = uri + sizeof(prefix) - 1;
    const char* q = strchr(label, '?');
    if (!q) return false;

    char name[64];
    size_t ln = (size_t)(q - label) < sizeof(name) - 1 ? (size_t)(q - label) : sizeof(name) - 1;
    memcpy(name, label, ln);
    name[ln] = '\0';
    urlDecodeInPlace(name);

    char val[128];
    if (!queryParam(q + 1, "secret", val, sizeof(val))) return false;
    // Prefer "Issuer:account" label; fall back to issuer parameter.
    if (!fromBase32(name, val, out)) return false;
    if (strchr(name, ':') == nullptr && queryParam(q + 1, "issuer", val, sizeof(val))) {
        char combined[200];
        snprintf(combined, sizeof(combined), "%s:%s", val, name);
        strlcpy(out->name, combined, sizeof(out->name));
    }
    if (queryParam(q + 1, "digits", val, sizeof(val))) {
        int d = atoi(val);
        if (d != 6 && d != 8) return false;
        out->digits = (uint8_t)d;
    }
    if (queryParam(q + 1, "period", val, sizeof(val))) {
        int p = atoi(val);
        if (p < 1 || p > 255) return false;
        out->period = (uint8_t)p;
    }
    if (queryParam(q + 1, "algorithm", val, sizeof(val))) {
        if (!strcasecmp(val, "SHA1")) out->algo = 1;
        else if (!strcasecmp(val, "SHA256")) out->algo = 256;
        else if (!strcasecmp(val, "SHA512")) out->algo = 512;
        else return false;
    }
    return true;
}

}  // namespace totp
