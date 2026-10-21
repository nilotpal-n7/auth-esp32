#include "core/settings.h"
#include "core/log.h"
#include "crypto/crypto.h"
#include "config.h"
#include <Preferences.h>

namespace settings {

static Preferences s_prefs;
static uint8_t  s_masterKey[32];
static uint32_t s_counter = 0;
static bool     s_autoApprove = false;
static char     s_tz[48] = DEFAULT_TZ;
static bool     s_portalAuto = true;
static bool     s_keyboard = true;

// PIN record: salt(16) || SHA256(salt || pin)(32)
static uint8_t  s_pinRecord[48];
static bool     s_pinSet = false;
static uint8_t  s_pinRetries = FIDO_PIN_MAX_RETRIES;

static bool     s_uvActive = false;
static uint32_t s_uvStartMs = 0;
static int      s_uvHours = 12;

bool init() {
    if (!s_prefs.begin("sys", false)) {
        logf("SET", "NVS open failed");
        return false;
    }
    if (!s_prefs.isKey("mkey") || s_prefs.getBytes("mkey", s_masterKey, 32) != 32) {
        regenerateMasterKey();
        logf("SET", "Generated new FIDO master key");
    }
    s_counter     = s_prefs.getUInt("ctr", 0);
    s_autoApprove = s_prefs.getBool("auto", false);
    s_portalAuto  = s_prefs.getBool("portal", true);
    s_keyboard    = s_prefs.getBool("kbd", true);
    if (s_prefs.isKey("tz")) s_prefs.getString("tz", s_tz, sizeof(s_tz));
    if (s_tz[0] == '\0') strlcpy(s_tz, DEFAULT_TZ, sizeof(s_tz));
    s_pinSet      = s_prefs.isKey("pin") &&
                    s_prefs.getBytes("pin", s_pinRecord, sizeof(s_pinRecord)) == sizeof(s_pinRecord);
    s_pinRetries  = s_prefs.getUChar("pinTry", FIDO_PIN_MAX_RETRIES);
    s_uvHours     = s_prefs.getInt("uvh", 12);
    return true;
}

bool autoApprove() { return s_autoApprove; }
void setAutoApprove(bool on) {
    s_autoApprove = on;
    s_prefs.putBool("auto", on);
}

bool portalAuto() { return s_portalAuto; }
void setPortalAuto(bool on) {
    s_portalAuto = on;
    s_prefs.putBool("portal", on);
}

bool keyboard() { return s_keyboard; }
void setKeyboard(bool on) {
    s_keyboard = on;
    s_prefs.putBool("kbd", on);
}

const char* timezone() { return s_tz; }
void setTimezone(const char* tz) {
    strlcpy(s_tz, tz, sizeof(s_tz));
    s_prefs.putString("tz", s_tz);
}

const uint8_t* masterKey() { return s_masterKey; }

void regenerateMasterKey() {
    crypto::random(s_masterKey, sizeof(s_masterKey));
    s_prefs.putBytes("mkey", s_masterKey, sizeof(s_masterKey));
}

void restoreFido(const uint8_t master[32], uint32_t counter) {
    memcpy(s_masterKey, master, 32);
    s_prefs.putBytes("mkey", s_masterKey, sizeof(s_masterKey));
    // Margin: the old device may have signed more since the backup was made.
    uint32_t c = (counter > s_counter ? counter : s_counter) + 10000;
    s_counter = c;
    s_prefs.putUInt("ctr", s_counter);
    s_uvActive = false;
}

uint32_t signCount() { return s_counter; }
uint32_t nextSignCount() {
    s_counter++;
    s_prefs.putUInt("ctr", s_counter);
    return s_counter;
}

// --- PIN ---------------------------------------------------------------------

static void pinHash(const uint8_t salt[16], const char* pin, uint8_t out[32]) {
    crypto::Sha256 h;
    h.update(salt, 16);
    h.update((const uint8_t*)pin, strlen(pin));
    h.finish(out);
}

static bool pinWellFormed(const char* pin) {
    size_t n = strlen(pin);
    if (n < FIDO_PIN_MIN_LEN || n > FIDO_PIN_MAX_LEN) return false;
    for (size_t i = 0; i < n; i++) if (pin[i] < '0' || pin[i] > '9') return false;
    return true;
}

bool pinIsSet() { return s_pinSet; }
int  pinRetries() { return s_pinRetries; }

bool pinSet(const char* pin) {
    if (!pinWellFormed(pin)) return false;
    crypto::random(s_pinRecord, 16);
    pinHash(s_pinRecord, pin, s_pinRecord + 16);
    s_prefs.putBytes("pin", s_pinRecord, sizeof(s_pinRecord));
    s_pinSet = true;
    s_pinRetries = FIDO_PIN_MAX_RETRIES;
    s_prefs.putUChar("pinTry", s_pinRetries);
    return true;
}

bool pinVerify(const char* pin) {
    if (!s_pinSet || s_pinRetries == 0) return false;
    // Count the attempt before checking so power-cycling can't grant free tries.
    s_pinRetries--;
    s_prefs.putUChar("pinTry", s_pinRetries);
    uint8_t h[32];
    pinHash(s_pinRecord, pin, h);
    bool ok = crypto::equal(h, s_pinRecord + 16, 32);
    if (ok) {
        s_pinRetries = FIDO_PIN_MAX_RETRIES;
        s_prefs.putUChar("pinTry", s_pinRetries);
    }
    return ok;
}

void uvSessionStart() {
    s_uvActive = true;
    s_uvStartMs = millis();
}

void uvSessionEnd() { s_uvActive = false; }

bool uvSessionActive() {
    if (!s_uvActive || !s_pinSet) return false;
    if (s_uvHours > 0 && millis() - s_uvStartMs >= (uint32_t)s_uvHours * 3600000UL) s_uvActive = false;
    return s_uvActive;
}

uint32_t uvSessionMinutesLeft() {
    if (!uvSessionActive()) return 0;
    if (s_uvHours == 0) return UINT32_MAX;
    return ((uint32_t)s_uvHours * 3600000UL - (millis() - s_uvStartMs)) / 60000UL;
}

int uvSessionHours() { return s_uvHours; }

void setUvSessionHours(int hours) {
    s_uvHours = hours < 0 ? 0 : hours > 168 ? 168 : hours;
    s_prefs.putInt("uvh", s_uvHours);
}

void pinClear() {
    s_uvActive = false;
    if (s_prefs.isKey("pin")) s_prefs.remove("pin");
    if (s_prefs.isKey("pinTry")) s_prefs.remove("pinTry");
    s_pinSet = false;
    s_pinRetries = FIDO_PIN_MAX_RETRIES;
    crypto::wipe(s_pinRecord, sizeof(s_pinRecord));
}

void resetFido() {
    s_uvActive = false;
    regenerateMasterKey();
    s_counter = 0;
    s_prefs.putUInt("ctr", 0);
    pinClear();
}

}  // namespace settings
