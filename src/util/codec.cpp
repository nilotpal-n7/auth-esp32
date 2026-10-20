#include "util/codec.h"
#include <string.h>
#include <ctype.h>

void hexEncode(const uint8_t* in, size_t len, char* out, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[2 * len] = '\0';
}

static int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hexDecode(const char* in, size_t inLen, uint8_t* out, size_t cap) {
    if (inLen % 2) return -1;
    if (inLen / 2 > cap) return -1;
    for (size_t i = 0; i < inLen / 2; i++) {
        int hi = hexNibble(in[2 * i]), lo = hexNibble(in[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(inLen / 2);
}

int base32Decode(const char* in, uint8_t* out, size_t cap) {
    uint32_t buffer = 0;
    int bits = 0;
    size_t n = 0;
    for (; *in; in++) {
        char c = *in;
        int v;
        if (c == ' ' || c == '-' || c == '=') continue;
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else return -1;
        buffer = (buffer << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return -1;
            out[n++] = (uint8_t)(buffer >> bits);
        }
    }
    return (int)n;
}

void base32Encode(const uint8_t* in, size_t len, char* out, size_t cap) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    uint32_t buffer = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | in[i];
        bits += 8;
        while (bits >= 5 && n + 1 < cap) {
            bits -= 5;
            out[n++] = alphabet[(buffer >> bits) & 31];
        }
    }
    if (bits > 0 && n + 1 < cap) out[n++] = alphabet[(buffer << (5 - bits)) & 31];
    if (cap) out[n] = '\0';
}

void urlDecodeInPlace(char* s) {
    char* w = s;
    for (char* r = s; *r; r++) {
        if (*r == '%' && hexNibble(r[1]) >= 0 && hexNibble(r[2]) >= 0) {
            *w++ = (char)((hexNibble(r[1]) << 4) | hexNibble(r[2]));
            r += 2;
        } else if (*r == '+') {
            *w++ = ' ';
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

// Chromium device/fido/cable/v2_handshake.cc: DigitsToBytes. Each 7-byte chunk
// is a little-endian integer written as 17 decimal digits; a shorter final
// chunk uses the width table below.
int fidoQrDigitsToBytes(const char* in, uint8_t* out, size_t cap) {
    static const int kWidths[8] = {0, 3, 5, 8, 10, 13, 15, 17};
    size_t len = strlen(in);
    size_t n = 0;
    while (len > 0) {
        size_t digits = len >= 17 ? 17 : len;
        int bytes = -1;
        for (int b = 1; b <= 7; b++) if ((size_t)kWidths[b] == digits) bytes = b;
        if (bytes < 0) return -1;
        uint64_t v = 0;
        for (size_t i = 0; i < digits; i++) {
            if (!isdigit((unsigned char)in[i])) return -1;
            v = v * 10 + (uint64_t)(in[i] - '0');
        }
        if (bytes < 8 && (v >> (8 * bytes)) != 0) return -1;
        if (n + bytes > cap) return -1;
        for (int b = 0; b < bytes; b++) out[n++] = (uint8_t)(v >> (8 * b));
        in += digits;
        len -= digits;
    }
    return (int)n;
}
