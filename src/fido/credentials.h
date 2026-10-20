// =============================================================================
// fido/credentials.h — credential IDs, key derivation, discoverable storage
//
// Private keys are never stored. Every credential ID carries a random nonce
// and a MAC bound to the RP ID hash; the private key is re-derived from the
// device master key on use:
//
//   credId = type(1) || nonce(16) || HMAC(macKey, type||nonce||rpIdHash)[:16]
//   priv   = HMAC(keyKey, nonce || rpIdHash)       (retried until valid)
//
// Discoverable (resident) credentials additionally store the user entity in
// NVS so they can be listed without an allowList.
// =============================================================================
#pragma once

#include <Arduino.h>
#include "config.h"

#define CRED_ID_LEN       33
#define CRED_TYPE_PLAIN   0xA1
#define CRED_TYPE_RESIDENT 0xA2
#define USER_ID_MAX       64
#define USER_NAME_MAX     40
#define RP_ID_MAX         64

struct ResidentCredential {
    uint8_t  credId[CRED_ID_LEN];
    uint8_t  rpIdHash[32];
    char     rpId[RP_ID_MAX];
    uint8_t  userId[USER_ID_MAX];
    uint8_t  userIdLen;
    char     userName[USER_NAME_MAX];
    char     displayName[USER_NAME_MAX];
    uint32_t created;      // monotonic creation order (newest = highest)
};

namespace creds {

void init();

// Create a new credential ID and its key pair for `rpIdHash`.
bool create(const uint8_t rpIdHash[32], bool resident,
            uint8_t credId[CRED_ID_LEN], uint8_t pub[65], uint8_t priv[32]);

// Verify that `credId` was issued by this device for `rpIdHash` and derive
// its private key. Returns false for foreign or tampered IDs.
bool derive(const uint8_t* credId, size_t len, const uint8_t rpIdHash[32], uint8_t priv[32]);

// --- Discoverable credential store ---
int  residentCount();
int  residentCapacity();
bool residentGet(int slot, ResidentCredential* out);     // slot in [0, capacity)
// Store, replacing an existing credential with the same RP + user ID.
bool residentPut(const ResidentCredential& c);
// Slots matching rpIdHash, newest first. Returns count written to `slots`.
int  residentFind(const uint8_t rpIdHash[32], int* slots, int maxSlots);
bool residentDelete(int slot);
void residentWipe();

}  // namespace creds
