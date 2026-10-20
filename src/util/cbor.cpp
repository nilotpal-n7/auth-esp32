#include "util/cbor.h"
#include <string.h>

// --- Writer ------------------------------------------------------------------

void CborWriter::raw(const uint8_t* p, size_t n) {
    if (!m_ok) return;
    if (n > m_cap - m_len) { m_ok = false; return; }
    if (n) memcpy(m_buf + m_len, p, n);
    m_len += n;
}

void CborWriter::head(uint8_t major, uint64_t v) {
    uint8_t h[9];
    size_t n;
    major <<= 5;
    if (v < 24)                { h[0] = major | (uint8_t)v; n = 1; }
    else if (v <= 0xFF)        { h[0] = major | 24; h[1] = (uint8_t)v; n = 2; }
    else if (v <= 0xFFFF)      { h[0] = major | 25; h[1] = v >> 8; h[2] = (uint8_t)v; n = 3; }
    else if (v <= 0xFFFFFFFFu) {
        h[0] = major | 26;
        for (int i = 0; i < 4; i++) h[1 + i] = (uint8_t)(v >> (24 - 8 * i));
        n = 5;
    } else {
        h[0] = major | 27;
        for (int i = 0; i < 8; i++) h[1 + i] = (uint8_t)(v >> (56 - 8 * i));
        n = 9;
    }
    raw(h, n);
}

void CborWriter::integer(int64_t v) {
    if (v >= 0) head(CBOR_UINT, (uint64_t)v);
    else        head(CBOR_NINT, (uint64_t)(-1 - v));
}

void CborWriter::text(const char* s) { text(s, strlen(s)); }

// --- Reader ------------------------------------------------------------------

uint8_t CborReader::peekMajor() const {
    if (!m_ok || m_p >= m_end) return 0xFF;
    return m_p[0] >> 5;
}

bool CborReader::readHead(uint8_t* major, uint64_t* arg) {
    if (!m_ok || m_p >= m_end) return fail();
    uint8_t ib = *m_p++;
    *major = ib >> 5;
    uint8_t info = ib & 0x1F;
    if (info < 24) { *arg = info; return true; }
    size_t n;
    switch (info) {
        case 24: n = 1; break;
        case 25: n = 2; break;
        case 26: n = 4; break;
        case 27: n = 8; break;
        default: return fail();   // indefinite lengths / reserved: not allowed in CTAP
    }
    if ((size_t)(m_end - m_p) < n) return fail();
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | *m_p++;
    *arg = v;
    return true;
}

bool CborReader::readUint(uint64_t* v) {
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a) || m != CBOR_UINT) return fail();
    *v = a;
    return true;
}

bool CborReader::readInt(int64_t* v) {
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a)) return false;
    if (a > (uint64_t)INT64_MAX) return fail();
    if (m == CBOR_UINT)      *v = (int64_t)a;
    else if (m == CBOR_NINT) *v = -1 - (int64_t)a;
    else return fail();
    return true;
}

bool CborReader::readBytes(const uint8_t** p, size_t* n) {
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a) || m != CBOR_BYTES) return fail();
    if (a > (uint64_t)(m_end - m_p)) return fail();
    *p = m_p; *n = (size_t)a; m_p += a;
    return true;
}

bool CborReader::readText(const char** s, size_t* n) {
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a) || m != CBOR_TEXT) return fail();
    if (a > (uint64_t)(m_end - m_p)) return fail();
    *s = (const char*)m_p; *n = (size_t)a; m_p += a;
    return true;
}

bool CborReader::readArray(size_t* n) {
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a) || m != CBOR_ARRAY) return fail();
    if (a > (uint64_t)(m_end - m_p)) return fail();   // each element >= 1 byte
    *n = (size_t)a;
    return true;
}

bool CborReader::readMap(size_t* n) {
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a) || m != CBOR_MAP) return fail();
    if (a > (uint64_t)(m_end - m_p) / 2) return fail();
    *n = (size_t)a;
    return true;
}

bool CborReader::readBool(bool* b) {
    if (!m_ok || m_p >= m_end) return fail();
    if (*m_p == 0xF5) { *b = true;  m_p++; return true; }
    if (*m_p == 0xF4) { *b = false; m_p++; return true; }
    return fail();
}

bool CborReader::readTextInto(char* out, size_t cap) {
    const char* s; size_t n;
    if (!readText(&s, &n)) return false;
    if (cap == 0) return true;
    size_t c = n < cap - 1 ? n : cap - 1;
    memcpy(out, s, c);
    out[c] = '\0';
    return true;
}

bool CborReader::readTextEquals(const char* s, bool* equal) {
    const char* t; size_t n;
    if (!readText(&t, &n)) return false;
    *equal = (strlen(s) == n) && memcmp(s, t, n) == 0;
    return true;
}

bool CborReader::skipDepth(int depth) {
    if (depth > 8) return fail();
    uint8_t m; uint64_t a;
    if (!readHead(&m, &a)) return false;
    switch (m) {
        case CBOR_UINT:
        case CBOR_NINT:
            return true;
        case CBOR_BYTES:
        case CBOR_TEXT:
            if (a > (uint64_t)(m_end - m_p)) return fail();
            m_p += a;
            return true;
        case CBOR_ARRAY:
            if (a > (uint64_t)(m_end - m_p)) return fail();
            for (uint64_t i = 0; i < a; i++) if (!skipDepth(depth + 1)) return false;
            return true;
        case CBOR_MAP:
            if (a > (uint64_t)(m_end - m_p) / 2) return fail();
            for (uint64_t i = 0; i < 2 * a; i++) if (!skipDepth(depth + 1)) return false;
            return true;
        case CBOR_TAG:
            return skipDepth(depth + 1);
        case CBOR_SIMPLE:
            // readHead already consumed the extra bytes of half/single/double floats.
            return true;
    }
    return fail();
}

bool CborReader::skip() { return skipDepth(0); }
