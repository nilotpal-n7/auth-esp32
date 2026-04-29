// =============================================================================
// totp.cpp — RFC 6238 TOTP Generator (HMAC-SHA1 via mbedTLS)
// =============================================================================

#include "totp.h"
#include "config.h"
#include <mbedtls/md.h>
#include <string.h>

// =============================================================================
// BASE32 DECODING
// =============================================================================

// Standard Base32 alphabet (RFC 4648)
static const char BASE32_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int base32CharValue(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';  // case-insensitive
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;  // Invalid character
}

size_t base32Decode(const char* encoded, uint8_t* output, size_t outputMaxLen) {
    size_t encodedLen = strlen(encoded);
    // Strip padding
    while (encodedLen > 0 && encoded[encodedLen - 1] == '=') {
        encodedLen--;
    }

    size_t outputIdx = 0;
    uint32_t buffer = 0;
    int bitsInBuffer = 0;

    for (size_t i = 0; i < encodedLen; i++) {
        int val = base32CharValue(encoded[i]);
        if (val < 0) continue;  // Skip invalid chars (spaces, etc.)

        buffer = (buffer << 5) | val;
        bitsInBuffer += 5;

        if (bitsInBuffer >= 8) {
            bitsInBuffer -= 8;
            if (outputIdx < outputMaxLen) {
                output[outputIdx++] = (uint8_t)((buffer >> bitsInBuffer) & 0xFF);
            }
        }
    }

    return outputIdx;
}

// =============================================================================
// HMAC-SHA1
// =============================================================================

static bool hmacSha1(const uint8_t* key, size_t keyLen,
                     const uint8_t* data, size_t dataLen,
                     uint8_t* output) {
    // output must be at least 20 bytes (SHA1 digest size)
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (mdInfo == NULL) return false;

    int ret = mbedtls_md_hmac(mdInfo, key, keyLen, data, dataLen, output);
    return (ret == 0);
}

// =============================================================================
// TOTP GENERATION (RFC 6238 / RFC 4226)
// =============================================================================

void totpInit() {
    // Nothing to initialize — mbedTLS is statically linked
    Serial.println("[TOTP] Engine initialized.");
}

uint32_t totpGenerate(const TotpAccount* account, time_t utcTimestamp) {
    // Step 1: Calculate time counter (T = floor(UTC / period))
    uint64_t timeCounter = (uint64_t)utcTimestamp / TOTP_PERIOD;

    // Step 2: Convert counter to big-endian 8-byte buffer
    uint8_t counterBytes[8];
    for (int i = 7; i >= 0; i--) {
        counterBytes[i] = (uint8_t)(timeCounter & 0xFF);
        timeCounter >>= 8;
    }

    // Step 3: HMAC-SHA1(secret, counter)
    uint8_t hmac[20];
    if (!hmacSha1(account->secret, account->secretLen, counterBytes, 8, hmac)) {
        Serial.println("[TOTP] HMAC-SHA1 failed!");
        return 0;
    }

    // Step 4: Dynamic truncation (RFC 4226 Section 5.4)
    uint8_t offset = hmac[19] & 0x0F;
    uint32_t truncated = ((uint32_t)(hmac[offset] & 0x7F) << 24)
                       | ((uint32_t)(hmac[offset + 1]) << 16)
                       | ((uint32_t)(hmac[offset + 2]) << 8)
                       | ((uint32_t)(hmac[offset + 3]));

    // Step 5: Modulo to get N-digit code
    uint32_t modulus = 1;
    for (int i = 0; i < TOTP_DIGITS; i++) modulus *= 10;

    return truncated % modulus;
}

uint8_t totpSecondsRemaining(time_t utcTimestamp) {
    return TOTP_PERIOD - (uint8_t)(utcTimestamp % TOTP_PERIOD);
}

void totpFormatCode(uint32_t code, char* buffer, size_t bufLen) {
    // Format as "XXX XXX" (with space in middle)
    if (TOTP_DIGITS == 6 && bufLen >= 8) {
        uint32_t first = code / 1000;
        uint32_t second = code % 1000;
        snprintf(buffer, bufLen, "%03u %03u", first, second);
    } else {
        snprintf(buffer, bufLen, "%0*u", TOTP_DIGITS, code);
    }
}
