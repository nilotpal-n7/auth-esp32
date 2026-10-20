// =============================================================================
// totp/totp.h — RFC 6238 TOTP accounts, storage and code generation
// =============================================================================
#pragma once

#include <Arduino.h>
#include <time.h>

#define TOTP_NAME_LEN    24
#define TOTP_SECRET_MAX  64

struct TotpAccount {
    char     name[TOTP_NAME_LEN];
    uint8_t  secret[TOTP_SECRET_MAX];
    uint8_t  secretLen;
    uint8_t  digits;       // 6 or 8
    uint8_t  period;       // seconds, usually 30
    uint16_t algo;         // 1 (SHA1), 256 or 512
};

namespace totp {

void init();

// Code for `account` at UTC unix time `now`.
uint32_t generate(const TotpAccount& account, time_t now);
uint8_t  secondsRemaining(const TotpAccount& account, time_t now);
// "123 456" / "1234 5678"
void     format(const TotpAccount& account, uint32_t code, char* out, size_t cap);

// --- Storage ---
int  count();
bool get(int index, TotpAccount* out);
// Returns new index or -1 (full / invalid).
int  add(const TotpAccount& account);
bool remove(int index);

// Parse "otpauth://totp/Label?secret=...&digits=..&period=..&algorithm=.."
// or "<name> <base32>" into an account. Returns false on invalid input.
bool parseUri(const char* uri, TotpAccount* out);
bool fromBase32(const char* name, const char* base32, TotpAccount* out);

}  // namespace totp
