// =============================================================================
// credential_store.h — NVS-Backed Credential Database
// =============================================================================
#pragma once

#include <Arduino.h>
#include "config.h"
#include "totp.h"

// =============================================================================
// FIDO2 CREDENTIAL STRUCTURE
// =============================================================================

struct FidoCredential {
    uint8_t  credentialId[FIDO2_CRED_ID_LEN];   // Random credential identifier
    uint8_t  privateKey[FIDO2_PRIVKEY_LEN];      // ECDSA P-256 private key
    uint8_t  publicKey[FIDO2_PUBKEY_LEN];        // ECDSA P-256 public key (uncompressed)
    char     rpId[FIDO2_RP_ID_MAX_LEN];          // Relying Party ID (e.g., "github.com")
    char     userName[FIDO2_USER_NAME_MAX_LEN];  // User display name
    uint8_t  userId[FIDO2_USER_ID_MAX_LEN];      // User handle (binary)
    size_t   userIdLen;                           // Length of user handle
    uint32_t signCounter;                         // Monotonic signature counter
    bool     valid;                               // Slot in use
};

// =============================================================================
// CREDENTIAL STORE API
// =============================================================================

// Initialize NVS credential store. Call once in setup().
void credStoreInit();

// --- FIDO2 Credentials ---

// Store a new FIDO2 credential. Returns the slot index, or -1 on failure.
int credStoreSaveFido(const FidoCredential* cred);

// Find a FIDO2 credential by Relying Party ID.
// If multiple credentials exist for the same RP, returns the first match.
// Returns true if found and populates *cred.
bool credStoreFindByRpId(const char* rpId, FidoCredential* cred);

// Find a FIDO2 credential by credential ID.
bool credStoreFindByCredId(const uint8_t* credId, size_t credIdLen, FidoCredential* cred);

// Increment and return the signature counter for a credential (by credential ID).
uint32_t credStoreIncrementCounter(const uint8_t* credId);

// Get the total number of stored FIDO2 credentials.
int credStoreCountFido();

// Delete a FIDO2 credential by credential ID.
bool credStoreDeleteFido(const uint8_t* credId);

// --- TOTP Accounts ---

// Store a new TOTP account. Returns the slot index, or -1 on failure.
int credStoreSaveTotp(const char* name, const char* base32Secret);

// Load a TOTP account by index (0-based). Returns true if the slot is valid.
bool credStoreLoadTotp(int index, TotpAccount* account);

// Get the total number of stored TOTP accounts.
int credStoreCountTotp();

// Delete a TOTP account by index.
bool credStoreDeleteTotp(int index);
