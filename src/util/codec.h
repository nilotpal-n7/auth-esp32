// =============================================================================
// util/codec.h — hex / base32 / URL helpers
// =============================================================================
#pragma once

#include <stdint.h>
#include <stddef.h>

// Lower- or upper-case hex. `out` must hold 2*len+1 chars.
void hexEncode(const uint8_t* in, size_t len, char* out, bool upper = false);
// Returns decoded length, or -1 on invalid input / overflow.
int  hexDecode(const char* in, size_t inLen, uint8_t* out, size_t cap);

// RFC 4648 base32 (case-insensitive, ignores spaces, '-' and '=' padding).
// Returns decoded length, or -1 on invalid characters / overflow.
int  base32Decode(const char* in, uint8_t* out, size_t cap);
void base32Encode(const uint8_t* in, size_t len, char* out, size_t cap);

// Percent-decode in place (for otpauth:// URIs).
void urlDecodeInPlace(char* s);

// caBLE "FIDO:/" QR digit encoding -> bytes. Returns length or -1.
int  fidoQrDigitsToBytes(const char* digits, uint8_t* out, size_t cap);
