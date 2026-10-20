// =============================================================================
// net/ws_client.h — minimal RFC 6455 WebSocket client over TLS
//
// Just enough for the caBLE tunnel: binary messages, ping/pong, close, and
// access to the handshake response headers (X-caBLE-Routing-ID).
// =============================================================================
#pragma once

#include <Arduino.h>
#include <WiFiClientSecure.h>

class WsClient {
public:
    // Blocking connect + upgrade. `headerName`/`headerValue` capture one
    // response header (case-insensitive name), e.g. the routing ID.
    bool connect(const char* host, const char* path, const char* protocol,
                 const char* caPem, const char* headerName,
                 char* headerValue, size_t headerCap);
    bool sendBinary(const uint8_t* data, size_t len);
    // 1 = message in `out`, 0 = nothing yet, -1 = closed / error.
    int  poll(uint8_t* out, size_t cap, size_t* len);
    void close();
    bool isOpen() const { return m_open; }

private:
    bool sendFrame(uint8_t opcode, const uint8_t* data, size_t len);
    bool readLine(char* buf, size_t cap, uint32_t timeoutMs);

    WiFiClientSecure m_tls;
    bool     m_open = false;
    // Incoming frame parser state
    uint8_t  m_hdr[14];
    size_t   m_hdrLen = 0;
    size_t   m_need = 0;           // payload bytes still to read for this frame
    uint8_t  m_opcode = 0;
    bool     m_fin = false;
    bool     m_inPayload = false;
    uint8_t  m_msg[1100];
    size_t   m_msgLen = 0;
    uint8_t  m_msgOpcode = 0;
    uint8_t  m_ctl[128];
    size_t   m_ctlLen = 0;
    bool     m_overflow = false;
};
