#include "net/ws_client.h"
#include "core/log.h"
#include "crypto/crypto.h"
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#define WS_OP_CONT   0x0
#define WS_OP_TEXT   0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

bool WsClient::readLine(char* buf, size_t cap, uint32_t timeoutMs) {
    size_t n = 0;
    uint32_t start = millis();
    while (millis() - start < timeoutMs) {
        if (!m_tls.available()) {
            if (!m_tls.connected()) return false;
            delay(2);
            continue;
        }
        int c = m_tls.read();
        if (c < 0) continue;
        if (c == '\n') {
            if (n && buf[n - 1] == '\r') n--;
            buf[n] = '\0';
            return true;
        }
        if (n + 1 < cap) buf[n++] = (char)c;
    }
    return false;
}

bool WsClient::connect(const char* host, const char* path, const char* protocol,
                       const char* caPem, const char* headerName,
                       char* headerValue, size_t headerCap) {
    close();
    if (headerValue && headerCap) headerValue[0] = '\0';
    m_tls.setCACert(caPem);
    m_tls.setHandshakeTimeout(15);
    if (!m_tls.connect(host, 443)) {
        char err[96] = "";
        m_tls.lastError(err, sizeof(err));
        logf("WS", "TLS connect to %s failed: %s", host, err);
        return false;
    }

    uint8_t keyRaw[16];
    crypto::random(keyRaw, sizeof(keyRaw));
    unsigned char key[32];
    size_t keyLen = 0;
    mbedtls_base64_encode(key, sizeof(key), &keyLen, keyRaw, sizeof(keyRaw));
    key[keyLen] = '\0';

    char req[384];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: %s\r\n"
                     "\r\n",
                     path, host, key, protocol);
    m_tls.write((const uint8_t*)req, n);

    char line[256];
    if (!readLine(line, sizeof(line), 10000) || strncmp(line, "HTTP/1.1 101", 12) != 0) {
        logf("WS", "upgrade rejected: %s", line);
        m_tls.stop();
        return false;
    }

    // Expected Sec-WebSocket-Accept = base64(SHA1(key + GUID))
    char expectAccept[40];
    {
        static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        uint8_t sha[20];
        mbedtls_sha1_context c;
        mbedtls_sha1_init(&c);
        mbedtls_sha1_starts_ret(&c);
        mbedtls_sha1_update_ret(&c, key, keyLen);
        mbedtls_sha1_update_ret(&c, (const uint8_t*)guid, sizeof(guid) - 1);
        mbedtls_sha1_finish_ret(&c, sha);
        mbedtls_sha1_free(&c);
        size_t al = 0;
        mbedtls_base64_encode((unsigned char*)expectAccept, sizeof(expectAccept), &al, sha, 20);
        expectAccept[al] = '\0';
    }

    bool acceptOk = false, protocolOk = false;
    while (readLine(line, sizeof(line), 5000)) {
        if (line[0] == '\0') break;   // end of headers
        char* colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char* value = colon + 1;
        while (*value == ' ') value++;
        if (!strcasecmp(line, "Sec-WebSocket-Accept")) acceptOk = !strcmp(value, expectAccept);
        else if (!strcasecmp(line, "Sec-WebSocket-Protocol")) protocolOk = !strcmp(value, protocol);
        if (headerName && !strcasecmp(line, headerName) && headerValue) {
            strlcpy(headerValue, value, headerCap);
        }
    }
    if (!acceptOk || !protocolOk) {
        logf("WS", "bad upgrade response (accept=%d protocol=%d)", acceptOk, protocolOk);
        m_tls.stop();
        return false;
    }

    m_open = true;
    m_hdrLen = 0;
    m_inPayload = false;
    m_msgLen = 0;
    m_overflow = false;
    return true;
}

bool WsClient::sendFrame(uint8_t opcode, const uint8_t* data, size_t len) {
    if (!m_open) return false;
    uint8_t hdr[14];
    size_t h = 0;
    hdr[h++] = 0x80 | opcode;                    // FIN
    if (len < 126) hdr[h++] = 0x80 | (uint8_t)len;
    else if (len <= 0xFFFF) { hdr[h++] = 0x80 | 126; hdr[h++] = len >> 8; hdr[h++] = (uint8_t)len; }
    else return false;
    uint8_t mask[4];
    crypto::random(mask, 4);
    memcpy(hdr + h, mask, 4);
    h += 4;

    static uint8_t frame[1200];
    if (h + len > sizeof(frame)) return false;
    memcpy(frame, hdr, h);
    for (size_t i = 0; i < len; i++) frame[h + i] = data[i] ^ mask[i & 3];
    size_t total = h + len;
    return m_tls.write(frame, total) == total;
}

bool WsClient::sendBinary(const uint8_t* data, size_t len) {
    return sendFrame(WS_OP_BINARY, data, len);
}

int WsClient::poll(uint8_t* out, size_t cap, size_t* outLen) {
    if (!m_open) return -1;
    if (!m_tls.connected() && !m_tls.available()) { m_open = false; return -1; }

    while (m_tls.available()) {
        if (!m_inPayload) {
            int c = m_tls.read();
            if (c < 0) break;
            m_hdr[m_hdrLen++] = (uint8_t)c;
            if (m_hdrLen < 2) continue;
            size_t need = 2;
            uint8_t l7 = m_hdr[1] & 0x7F;
            if (l7 == 126) need += 2;
            else if (l7 == 127) need += 8;
            if (m_hdr[1] & 0x80) need += 4;        // servers must not mask, tolerate anyway
            if (m_hdrLen < need) continue;

            m_fin = m_hdr[0] & 0x80;
            m_opcode = m_hdr[0] & 0x0F;
            uint64_t plen = l7;
            if (l7 == 126) plen = ((uint16_t)m_hdr[2] << 8) | m_hdr[3];
            else if (l7 == 127) {
                plen = 0;
                for (int i = 0; i < 8; i++) plen = (plen << 8) | m_hdr[2 + i];
            }
            m_need = (size_t)plen;
            m_hdrLen = 0;
            m_inPayload = true;
            m_ctlLen = 0;
            if (m_opcode == WS_OP_BINARY || m_opcode == WS_OP_TEXT) {
                m_msgLen = 0;
                m_overflow = false;
                m_msgOpcode = m_opcode;
            }
        }
        if (m_inPayload) {
            while (m_need > 0 && m_tls.available()) {
                uint8_t tmp[128];
                size_t chunk = m_need < sizeof(tmp) ? m_need : sizeof(tmp);
                int r = m_tls.read(tmp, chunk);
                if (r <= 0) break;
                m_need -= r;
                if (m_opcode >= 0x8) {
                    size_t c = (size_t)r;
                    if (m_ctlLen + c > sizeof(m_ctl)) c = sizeof(m_ctl) - m_ctlLen;
                    memcpy(m_ctl + m_ctlLen, tmp, c);
                    m_ctlLen += c;
                } else if (m_msgLen + r <= sizeof(m_msg)) {
                    memcpy(m_msg + m_msgLen, tmp, r);
                    m_msgLen += r;
                } else {
                    m_overflow = true;
                }
            }
            if (m_need > 0) break;
            m_inPayload = false;

            switch (m_opcode) {
                case WS_OP_PING:
                    sendFrame(WS_OP_PONG, m_ctl, m_ctlLen);
                    break;
                case WS_OP_PONG:
                    break;
                case WS_OP_CLOSE:
                    sendFrame(WS_OP_CLOSE, m_ctl, m_ctlLen > 2 ? 2 : m_ctlLen);
                    close();
                    return -1;
                default:
                    if (m_fin && m_msgOpcode == WS_OP_BINARY) {
                        if (m_overflow || m_msgLen > cap) {
                            logf("WS", "message too large, dropped");
                            break;
                        }
                        memcpy(out, m_msg, m_msgLen);
                        *outLen = m_msgLen;
                        return 1;
                    }
                    break;
            }
        }
    }
    return 0;
}

void WsClient::close() {
    if (m_open) m_tls.stop();
    m_open = false;
}
