// =============================================================================
// util/cbor.h — minimal, bounds-checked CBOR encoder / decoder (RFC 8949)
//
// Supports what CTAP2 needs: definite-length ints, byte/text strings, arrays,
// maps and simple values. Every read is bounds checked; any malformed input
// puts the reader into a sticky error state instead of reading out of range.
// =============================================================================
#pragma once

#include <stdint.h>
#include <stddef.h>

enum CborMajor : uint8_t {
    CBOR_UINT   = 0,
    CBOR_NINT   = 1,
    CBOR_BYTES  = 2,
    CBOR_TEXT   = 3,
    CBOR_ARRAY  = 4,
    CBOR_MAP    = 5,
    CBOR_TAG    = 6,
    CBOR_SIMPLE = 7,
};

class CborWriter {
public:
    CborWriter(uint8_t* buf, size_t cap) : m_buf(buf), m_cap(cap) {}

    void uint(uint64_t v)                  { head(CBOR_UINT, v); }
    void integer(int64_t v);
    void bytes(const uint8_t* p, size_t n) { head(CBOR_BYTES, n); raw(p, n); }
    void text(const char* s);
    void text(const char* s, size_t n)     { head(CBOR_TEXT, n); raw((const uint8_t*)s, n); }
    void array(size_t n)                   { head(CBOR_ARRAY, n); }
    void map(size_t n)                     { head(CBOR_MAP, n); }
    void boolean(bool b)                   { byte(b ? 0xF5 : 0xF4); }
    void null()                            { byte(0xF6); }
    void raw(const uint8_t* p, size_t n);

    size_t   size() const { return m_len; }
    bool     ok() const   { return m_ok; }
    uint8_t* data() const { return m_buf; }

private:
    void head(uint8_t major, uint64_t v);
    void byte(uint8_t b) { raw(&b, 1); }

    uint8_t* m_buf;
    size_t   m_cap;
    size_t   m_len = 0;
    bool     m_ok = true;
};

class CborReader {
public:
    CborReader(const uint8_t* p, size_t n) : m_p(p), m_end(p + n) {}

    // Type of the next item without consuming it (0xFF if at end / error).
    uint8_t peekMajor() const;
    bool    atEnd() const { return m_p >= m_end; }
    bool    ok() const    { return m_ok; }
    size_t  remaining() const { return m_ok ? (size_t)(m_end - m_p) : 0; }
    const uint8_t* pos() const { return m_p; }

    bool readUint(uint64_t* v);
    bool readInt(int64_t* v);                         // uint or nint
    bool readBytes(const uint8_t** p, size_t* n);
    bool readText(const char** s, size_t* n);
    bool readArray(size_t* n);
    bool readMap(size_t* n);
    bool readBool(bool* b);
    bool skip();                                      // skip one complete item

    // Copy a text string into a NUL-terminated buffer (truncating to fit).
    bool readTextInto(char* out, size_t cap);
    // True if the next item is a text string equal to `s` (consumes it).
    bool readTextEquals(const char* s, bool* equal);

private:
    bool readHead(uint8_t* major, uint64_t* arg);
    bool fail() { m_ok = false; return false; }
    bool skipDepth(int depth);

    const uint8_t* m_p;
    const uint8_t* m_end;
    bool m_ok = true;
};
