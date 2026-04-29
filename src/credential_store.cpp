// =============================================================================
// credential_store.cpp — NVS-Backed Credential Database
// =============================================================================

#include "credential_store.h"
#include <Preferences.h>
#include <string.h>

// Separate NVS namespaces for FIDO2 and TOTP
static Preferences s_fidoPrefs;
static Preferences s_totpPrefs;
static Preferences s_metaPrefs;

// =============================================================================
// HELPERS — Key naming for indexed storage
// =============================================================================

// Generate NVS key like "f0", "f1", ... "f199" for FIDO credentials
static void fidoKey(int index, char* buf, size_t bufLen) {
    snprintf(buf, bufLen, "f%d", index);
}

// Generate NVS key like "t0", "t1", ... for TOTP accounts
static void totpKey(int index, char* buf, size_t bufLen) {
    snprintf(buf, bufLen, "t%d", index);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

void credStoreInit() {
    Serial.println("[CRED] Initializing NVS credential store...");

    // Open namespaces (read-write)
    s_metaPrefs.begin("auth_meta", false);

    // Initialize counters if first boot
    if (!s_metaPrefs.isKey("fidoCount")) {
        s_metaPrefs.putInt("fidoCount", 0);
    }
    if (!s_metaPrefs.isKey("totpCount")) {
        s_metaPrefs.putInt("totpCount", 0);
    }

    int fc = s_metaPrefs.getInt("fidoCount", 0);
    int tc = s_metaPrefs.getInt("totpCount", 0);
    Serial.printf("[CRED] Loaded: %d FIDO2 credentials, %d TOTP accounts\n", fc, tc);
}

// =============================================================================
// FIDO2 CREDENTIAL OPERATIONS
// =============================================================================

int credStoreSaveFido(const FidoCredential* cred) {
    s_fidoPrefs.begin("auth_fido", false);
    s_metaPrefs.begin("auth_meta", false);

    int count = s_metaPrefs.getInt("fidoCount", 0);
    if (count >= FIDO2_MAX_CREDENTIALS) {
        Serial.println("[CRED] FIDO2 storage full!");
        s_fidoPrefs.end();
        s_metaPrefs.end();
        return -1;
    }

    // Serialize credential into a flat byte buffer
    char key[16];
    fidoKey(count, key, sizeof(key));

    size_t written = s_fidoPrefs.putBytes(key, (const uint8_t*)cred, sizeof(FidoCredential));
    if (written != sizeof(FidoCredential)) {
        Serial.println("[CRED] Failed to write FIDO2 credential!");
        s_fidoPrefs.end();
        s_metaPrefs.end();
        return -1;
    }

    count++;
    s_metaPrefs.putInt("fidoCount", count);

    Serial.printf("[CRED] Saved FIDO2 credential #%d for RP: %s\n", count - 1, cred->rpId);

    s_fidoPrefs.end();
    s_metaPrefs.end();
    return count - 1;
}

bool credStoreFindByRpId(const char* rpId, FidoCredential* cred) {
    s_fidoPrefs.begin("auth_fido", true);  // read-only
    s_metaPrefs.begin("auth_meta", true);

    int count = s_metaPrefs.getInt("fidoCount", 0);
    FidoCredential temp;
    char key[16];

    for (int i = 0; i < count; i++) {
        fidoKey(i, key, sizeof(key));
        size_t readLen = s_fidoPrefs.getBytes(key, (uint8_t*)&temp, sizeof(FidoCredential));
        if (readLen == sizeof(FidoCredential) && temp.valid) {
            if (strcmp(temp.rpId, rpId) == 0) {
                memcpy(cred, &temp, sizeof(FidoCredential));
                s_fidoPrefs.end();
                s_metaPrefs.end();
                return true;
            }
        }
    }

    s_fidoPrefs.end();
    s_metaPrefs.end();
    return false;
}

bool credStoreFindByCredId(const uint8_t* credId, size_t credIdLen, FidoCredential* cred) {
    if (credIdLen != FIDO2_CRED_ID_LEN) return false;

    s_fidoPrefs.begin("auth_fido", true);
    s_metaPrefs.begin("auth_meta", true);

    int count = s_metaPrefs.getInt("fidoCount", 0);
    FidoCredential temp;
    char key[16];

    for (int i = 0; i < count; i++) {
        fidoKey(i, key, sizeof(key));
        size_t readLen = s_fidoPrefs.getBytes(key, (uint8_t*)&temp, sizeof(FidoCredential));
        if (readLen == sizeof(FidoCredential) && temp.valid) {
            if (memcmp(temp.credentialId, credId, FIDO2_CRED_ID_LEN) == 0) {
                memcpy(cred, &temp, sizeof(FidoCredential));
                s_fidoPrefs.end();
                s_metaPrefs.end();
                return true;
            }
        }
    }

    s_fidoPrefs.end();
    s_metaPrefs.end();
    return false;
}

uint32_t credStoreIncrementCounter(const uint8_t* credId) {
    s_fidoPrefs.begin("auth_fido", false);
    s_metaPrefs.begin("auth_meta", true);

    int count = s_metaPrefs.getInt("fidoCount", 0);
    FidoCredential temp;
    char key[16];

    for (int i = 0; i < count; i++) {
        fidoKey(i, key, sizeof(key));
        size_t readLen = s_fidoPrefs.getBytes(key, (uint8_t*)&temp, sizeof(FidoCredential));
        if (readLen == sizeof(FidoCredential) && temp.valid) {
            if (memcmp(temp.credentialId, credId, FIDO2_CRED_ID_LEN) == 0) {
                temp.signCounter++;
                s_fidoPrefs.putBytes(key, (const uint8_t*)&temp, sizeof(FidoCredential));
                uint32_t counter = temp.signCounter;
                s_fidoPrefs.end();
                s_metaPrefs.end();
                return counter;
            }
        }
    }

    s_fidoPrefs.end();
    s_metaPrefs.end();
    return 0;
}

int credStoreCountFido() {
    s_metaPrefs.begin("auth_meta", true);
    int count = s_metaPrefs.getInt("fidoCount", 0);
    s_metaPrefs.end();
    return count;
}

bool credStoreDeleteFido(const uint8_t* credId) {
    s_fidoPrefs.begin("auth_fido", false);
    s_metaPrefs.begin("auth_meta", false);

    int count = s_metaPrefs.getInt("fidoCount", 0);
    FidoCredential temp;
    char key[16];

    for (int i = 0; i < count; i++) {
        fidoKey(i, key, sizeof(key));
        size_t readLen = s_fidoPrefs.getBytes(key, (uint8_t*)&temp, sizeof(FidoCredential));
        if (readLen == sizeof(FidoCredential) && temp.valid) {
            if (memcmp(temp.credentialId, credId, FIDO2_CRED_ID_LEN) == 0) {
                temp.valid = false;
                s_fidoPrefs.putBytes(key, (const uint8_t*)&temp, sizeof(FidoCredential));
                Serial.printf("[CRED] Deleted FIDO2 credential #%d\n", i);
                s_fidoPrefs.end();
                s_metaPrefs.end();
                return true;
            }
        }
    }

    s_fidoPrefs.end();
    s_metaPrefs.end();
    return false;
}

// =============================================================================
// TOTP ACCOUNT OPERATIONS
// =============================================================================

// Internal TOTP storage structure (includes the base32 secret for re-encoding)
struct TotpStorageEntry {
    char name[32];
    char base32Secret[64];    // Original Base32-encoded secret
    bool valid;
};

int credStoreSaveTotp(const char* name, const char* base32Secret) {
    s_totpPrefs.begin("auth_totp", false);
    s_metaPrefs.begin("auth_meta", false);

    int count = s_metaPrefs.getInt("totpCount", 0);
    if (count >= TOTP_MAX_ACCOUNTS) {
        Serial.println("[CRED] TOTP storage full!");
        s_totpPrefs.end();
        s_metaPrefs.end();
        return -1;
    }

    TotpStorageEntry entry;
    memset(&entry, 0, sizeof(entry));
    strncpy(entry.name, name, sizeof(entry.name) - 1);
    strncpy(entry.base32Secret, base32Secret, sizeof(entry.base32Secret) - 1);
    entry.valid = true;

    char key[16];
    totpKey(count, key, sizeof(key));

    s_totpPrefs.putBytes(key, (const uint8_t*)&entry, sizeof(TotpStorageEntry));

    count++;
    s_metaPrefs.putInt("totpCount", count);

    Serial.printf("[CRED] Saved TOTP account #%d: %s\n", count - 1, name);

    s_totpPrefs.end();
    s_metaPrefs.end();
    return count - 1;
}

bool credStoreLoadTotp(int index, TotpAccount* account) {
    s_totpPrefs.begin("auth_totp", true);
    s_metaPrefs.begin("auth_meta", true);

    int count = s_metaPrefs.getInt("totpCount", 0);
    if (index < 0 || index >= count) {
        s_totpPrefs.end();
        s_metaPrefs.end();
        return false;
    }

    TotpStorageEntry entry;
    char key[16];
    totpKey(index, key, sizeof(key));

    size_t readLen = s_totpPrefs.getBytes(key, (uint8_t*)&entry, sizeof(TotpStorageEntry));
    if (readLen != sizeof(TotpStorageEntry) || !entry.valid) {
        s_totpPrefs.end();
        s_metaPrefs.end();
        return false;
    }

    // Decode base32 secret into the TotpAccount
    memset(account, 0, sizeof(TotpAccount));
    strncpy(account->name, entry.name, sizeof(account->name) - 1);
    account->secretLen = base32Decode(entry.base32Secret, account->secret, sizeof(account->secret));

    s_totpPrefs.end();
    s_metaPrefs.end();
    return true;
}

int credStoreCountTotp() {
    s_metaPrefs.begin("auth_meta", true);
    int count = s_metaPrefs.getInt("totpCount", 0);
    s_metaPrefs.end();
    return count;
}

bool credStoreDeleteTotp(int index) {
    s_totpPrefs.begin("auth_totp", false);
    s_metaPrefs.begin("auth_meta", true);

    int count = s_metaPrefs.getInt("totpCount", 0);
    if (index < 0 || index >= count) {
        s_totpPrefs.end();
        s_metaPrefs.end();
        return false;
    }

    TotpStorageEntry entry;
    char key[16];
    totpKey(index, key, sizeof(key));

    size_t readLen = s_totpPrefs.getBytes(key, (uint8_t*)&entry, sizeof(TotpStorageEntry));
    if (readLen == sizeof(TotpStorageEntry)) {
        entry.valid = false;
        s_totpPrefs.putBytes(key, (const uint8_t*)&entry, sizeof(TotpStorageEntry));
        Serial.printf("[CRED] Deleted TOTP account #%d\n", index);
    }

    s_totpPrefs.end();
    s_metaPrefs.end();
    return true;
}
