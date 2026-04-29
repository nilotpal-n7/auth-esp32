// =============================================================================
// totp.h — RFC 6238 TOTP Generator (HMAC-SHA1 via mbedTLS)
// =============================================================================
#pragma once

#include <Arduino.h>

// A single TOTP account
struct TotpAccount {
    char name[32];              // Display name (e.g., "GitHub")
    uint8_t secret[32];         // Decoded binary secret (from Base32)
    size_t secretLen;           // Length of decoded secret in bytes
};

// Initialize the TOTP engine.
void totpInit();

// Decode a Base32-encoded string into raw bytes.
// Returns number of decoded bytes, or 0 on error.
size_t base32Decode(const char* encoded, uint8_t* output, size_t outputMaxLen);

// Generate a TOTP code for the given account at the given UTC timestamp.
// Returns the numeric code (e.g., 837291).
uint32_t totpGenerate(const TotpAccount* account, time_t utcTimestamp);

// Get the number of seconds remaining in the current TOTP window.
uint8_t totpSecondsRemaining(time_t utcTimestamp);

// Format a TOTP code as a string with a space in the middle (e.g., "837 291").
void totpFormatCode(uint32_t code, char* buffer, size_t bufLen);
