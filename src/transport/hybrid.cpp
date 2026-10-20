#include "transport/hybrid.h"
#include "transport/ble.h"
#include "net/network.h"
#include "net/tunnel_ca.h"
#include "net/ws_client.h"
#include "fido/ctap2.h"
#include "core/log.h"
#include "crypto/crypto.h"
#include "util/cbor.h"
#include "util/codec.h"

namespace hybrid {

// Chromium DerivedValueType
enum : uint32_t { kEIDKey = 1, kTunnelID = 2, kPSK = 3 };
enum : uint8_t  { kMsgShutdown = 0, kMsgCTAP = 1, kMsgUpdate = 2 };

static const char* TUNNEL_HOST = "cable.ua5v.com";   // assigned domain ID 0
static const uint32_t ADVERT_TIMEOUT_MS = 60000;
static const uint32_t IDLE_TIMEOUT_MS = 120000;

static State    s_state = State::Idle;
static char     s_status[32] = "idle";
static char     s_reqType[12] = "";
static uint8_t  s_secret[16];
static uint8_t  s_peerIdentity[65];
static uint8_t  s_psk[32];
static uint8_t  s_readKey[32], s_writeKey[32];
static uint32_t s_readSeq = 0, s_writeSeq = 0;
static uint32_t s_stateSince = 0, s_lastActivity = 0;
static bool     s_startPending = false;
static WsClient s_ws;
static uint8_t  s_buf[1200];

static void setState(State st, const char* text) {
    s_state = st;
    s_stateSince = millis();
    strlcpy(s_status, text, sizeof(s_status));
    ble::setHybridStatus(text);
    logf("HYBRID", "%s", text);
}

static void derive(const uint8_t* salt, size_t saltLen, uint32_t type, uint8_t* out, size_t outLen) {
    uint8_t info[4] = {(uint8_t)type, (uint8_t)(type >> 8), (uint8_t)(type >> 16), (uint8_t)(type >> 24)};
    crypto::hkdfSha256(s_secret, sizeof(s_secret), salt, saltLen, info, 4, out, outLen);
}

// --- Noise (Chromium device/fido/cable/noise.cc) ----------------------------

struct Noise {
    uint8_t ck[32], h[32], k[32];
    uint32_t n;

    void init(const char* name) {
        memset(ck, 0, 32);
        memcpy(ck, name, strlen(name));
        memcpy(h, ck, 32);
        n = 0;
    }
    void mixHash(const uint8_t* d, size_t len) {
        crypto::Sha256 s;
        s.update(h, 32);
        s.update(d, len);
        s.finish(h);
    }
    void mixKey(const uint8_t* ikm, size_t len) {
        uint8_t out[64];
        crypto::hkdfSha256(ikm, len, ck, 32, nullptr, 0, out, 64);
        memcpy(ck, out, 32);
        memcpy(k, out + 32, 32);
        n = 0;
    }
    void mixKeyAndHash(const uint8_t* ikm, size_t len) {
        uint8_t out[96];
        crypto::hkdfSha256(ikm, len, ck, 32, nullptr, 0, out, 96);
        memcpy(ck, out, 32);
        mixHash(out + 32, 32);
        memcpy(k, out + 64, 32);
        n = 0;
    }
    void nonce(uint8_t out[12]) {
        memset(out, 0, 12);
        out[0] = n >> 24; out[1] = n >> 16; out[2] = n >> 8; out[3] = n;   // big-endian prefix
        n++;
    }
    bool encryptAndHash(const uint8_t* pt, size_t len, uint8_t* out) {
        uint8_t iv[12];
        nonce(iv);
        if (!crypto::aesGcmSeal(k, iv, h, 32, pt, len, out)) return false;
        mixHash(out, len + 16);
        return true;
    }
    bool decryptAndHash(const uint8_t* ct, size_t len, uint8_t* out) {
        uint8_t iv[12];
        nonce(iv);
        if (!crypto::aesGcmOpen(k, iv, h, 32, ct, len, out)) return false;
        mixHash(ct, len);
        return true;
    }
};

// RespondToHandshake, KNpsk0 branch (QR-initiated, desktop identity known).
static bool respondToHandshake(const uint8_t* in, size_t len, uint8_t response[81]) {
    if (len != 65 + 16) {
        logf("HYBRID", "handshake message has wrong size %u", (unsigned)len);
        return false;
    }
    const uint8_t* peerEphemeral = in;
    Noise noise;
    noise.init("Noise_KNpsk0_P256_AESGCM_SHA256");
    uint8_t prologue = 1;
    noise.mixHash(&prologue, 1);
    noise.mixHash(s_peerIdentity, 65);
    noise.mixKeyAndHash(s_psk, 32);
    noise.mixHash(peerEphemeral, 65);
    noise.mixKey(peerEphemeral, 65);

    uint8_t empty[1];
    if (!noise.decryptAndHash(in + 65, 16, empty)) {
        logf("HYBRID", "handshake decrypt failed (wrong PSK / QR?)");
        return false;
    }

    uint8_t ePriv[32], ePub[65], shared[32];
    if (!crypto::p256Generate(ePriv, ePub)) { logf("HYBRID", "keygen failed"); return false; }
    noise.mixHash(ePub, 65);
    noise.mixKey(ePub, 65);
    if (!crypto::p256Ecdh(ePriv, peerEphemeral, shared)) { logf("HYBRID", "ECDH ee failed"); return false; }
    noise.mixKey(shared, 32);
    if (!crypto::p256Ecdh(ePriv, s_peerIdentity, shared)) { logf("HYBRID", "ECDH se failed"); return false; }
    noise.mixKey(shared, 32);
    crypto::wipe(ePriv, sizeof(ePriv));
    crypto::wipe(shared, sizeof(shared));

    memcpy(response, ePub, 65);
    if (!noise.encryptAndHash(nullptr, 0, response + 65)) { logf("HYBRID", "encrypt failed"); return false; }

    // traffic_keys(): HKDF2(ck, empty) -> (k1, k2); responder reads k1.
    uint8_t keys[64];
    crypto::hkdfSha256(nullptr, 0, noise.ck, 32, nullptr, 0, keys, 64);
    memcpy(s_readKey, keys, 32);
    memcpy(s_writeKey, keys + 32, 32);
    crypto::wipe(keys, sizeof(keys));
    s_readSeq = s_writeSeq = 0;
    return true;
}

// --- Crypter (post-handshake) ------------------------------------------------

static void crypterNonce(uint32_t seq, uint8_t out[12]) {
    memset(out, 0, 8);
    out[8] = seq >> 24; out[9] = seq >> 16; out[10] = seq >> 8; out[11] = seq;
}

static bool sendEncrypted(const uint8_t* msg, size_t len) {
    static uint8_t padded[1100], ct[1120];
    size_t paddedLen = (len + 1 + 31) & ~(size_t)31;
    if (paddedLen > sizeof(padded)) return false;
    memcpy(padded, msg, len);
    memset(padded + len, 0, paddedLen - len);
    padded[paddedLen - 1] = (uint8_t)(paddedLen - len - 1);
    uint8_t iv[12];
    crypterNonce(s_writeSeq++, iv);
    if (!crypto::aesGcmSeal(s_writeKey, iv, nullptr, 0, padded, paddedLen, ct)) return false;
    return s_ws.sendBinary(ct, paddedLen + 16);
}

static int decrypt(const uint8_t* ct, size_t len, uint8_t* out) {
    if (len < 16) return -1;
    uint8_t iv[12];
    crypterNonce(s_readSeq, iv);
    if (!crypto::aesGcmOpen(s_readKey, iv, nullptr, 0, ct, len, out)) return -1;
    s_readSeq++;
    size_t n = len - 16;
    if (n == 0) return -1;
    size_t pad = out[n - 1];
    if (pad + 1 > n) return -1;
    return (int)(n - pad - 1);
}

static void ctapReply(const uint8_t* data, size_t len) {
    static uint8_t msg[FIDO_MAX_MSG + 1];
    if (len > FIDO_MAX_MSG) return;
    msg[0] = kMsgCTAP;
    memcpy(msg + 1, data, len);
    if (!sendEncrypted(msg, len + 1)) logf("HYBRID", "failed to send reply");
    s_lastActivity = millis();
}

static bool sendPostHandshake() {
    uint8_t info[256];
    size_t infoLen = ctap::buildGetInfo(info, sizeof(info));
    uint8_t msg[320];
    CborWriter w(msg, sizeof(msg));
    w.map(2);
    w.uint(1); w.bytes(info, infoLen);
    w.uint(3); w.array(1); w.text("ctap");
    return infoLen && w.ok() && sendEncrypted(msg, w.size());
}

// --- QR parsing --------------------------------------------------------------

static bool parseQr(const char* text) {
    if (strncasecmp(text, "FIDO:/", 6) != 0) return false;
    uint8_t raw[256];
    int n = fidoQrDigitsToBytes(text + 6, raw, sizeof(raw));
    if (n <= 0) return false;

    CborReader r(raw, (size_t)n);
    size_t pairs;
    if (!r.readMap(&pairs)) return false;
    bool havePub = false, haveSecret = false;
    s_reqType[0] = '\0';
    for (size_t i = 0; i < pairs; i++) {
        uint64_t key;
        if (!r.readUint(&key)) return false;
        if (key == 0 || key == 1) {
            const uint8_t* b; size_t bl;
            if (!r.readBytes(&b, &bl)) return false;
            if (key == 0) {
                if (bl != 33 || !crypto::p256Decompress(b, s_peerIdentity)) return false;
                havePub = true;
            } else {
                if (bl != 16) return false;
                memcpy(s_secret, b, 16);
                haveSecret = true;
            }
        } else if (key == 5 && r.peekMajor() == CBOR_TEXT) {
            bool mc = false;
            r.readTextEquals("mc", &mc);
            strlcpy(s_reqType, mc ? "Register" : "Sign in", sizeof(s_reqType));
        } else {
            r.skip();
        }
        if (!r.ok()) return false;
    }
    return havePub && haveSecret;
}

// --- Session -----------------------------------------------------------------

bool start(const char* qrText) {
    if (s_state != State::Idle && s_state != State::Failed) stop("replaced");
    if (!parseQr(qrText)) {
        logf("HYBRID", "invalid FIDO QR data");
        setState(State::Failed, "bad QR");
        return false;
    }
    logEvent("Hybrid: %s", s_reqType[0] ? s_reqType : "request");
    setState(State::Connecting, "connecting");
    s_startPending = true;
    return true;
}

static void connectTunnel() {
    s_startPending = false;
    if (!network::ensureConnected()) {
        setState(State::Failed, "no WiFi");
        return;
    }

    uint8_t tunnelId[16];
    derive(nullptr, 0, kTunnelID, tunnelId, sizeof(tunnelId));
    char path[64] = "/cable/new/";
    hexEncode(tunnelId, sizeof(tunnelId), path + strlen(path), true);

    char routingHex[16];
    if (!s_ws.connect(TUNNEL_HOST, path, "fido.cable", TUNNEL_ROOT_CAS,
                      "X-caBLE-Routing-ID", routingHex, sizeof(routingHex))) {
        setState(State::Failed, "tunnel failed");
        return;
    }
    uint8_t routingId[3];
    if (hexDecode(routingHex, strlen(routingHex), routingId, 3) != 3) {
        logf("HYBRID", "missing/invalid routing ID '%s'", routingHex);
        s_ws.close();
        setState(State::Failed, "tunnel failed");
        return;
    }

    // EID plaintext: reserved(1)=0 | nonce(10) | routing ID(3) | domain ID (LE16)
    uint8_t eid[16] = {0};
    crypto::random(eid + 1, 10);
    memcpy(eid + 11, routingId, 3);
    eid[14] = 0; eid[15] = 0;

    uint8_t eidKey[64], advert[20], mac[32];
    derive(nullptr, 0, kEIDKey, eidKey, sizeof(eidKey));
    crypto::aes256EcbEncrypt(eidKey, eid, advert);
    crypto::hmacSha256(eidKey + 32, 32, advert, 16, mac);
    memcpy(advert + 16, mac, 4);
    derive(eid, sizeof(eid), kPSK, s_psk, sizeof(s_psk));

    ble::startHybridAdvert(advert);
    setState(State::Advertising, "waiting for PC");
}

void stop(const char* reason) {
    if (s_state == State::Idle) return;
    if (s_state == State::Ready && s_ws.isOpen()) {
        // Nothing to send: authenticators never send shutdown frames.
    }
    s_ws.close();
    ble::stopHybridAdvert();
    ctap::cancel(CtapTransport::Hybrid);
    crypto::wipe(s_secret, sizeof(s_secret));
    crypto::wipe(s_psk, sizeof(s_psk));
    crypto::wipe(s_readKey, sizeof(s_readKey));
    crypto::wipe(s_writeKey, sizeof(s_writeKey));
    s_startPending = false;
    setState(State::Idle, "idle");
    logf("HYBRID", "session ended: %s", reason);
}

void loop() {
    if (s_startPending) {
        connectTunnel();
        return;
    }
    if (s_state == State::Failed && millis() - s_stateSince > 5000) {
        s_state = State::Idle;
        strlcpy(s_status, "idle", sizeof(s_status));
        ble::stopHybridAdvert();
        return;
    }
    if (s_state != State::Advertising && s_state != State::Ready) return;

    if (s_state == State::Advertising && millis() - s_stateSince > ADVERT_TIMEOUT_MS) {
        stop("PC never connected");
        setState(State::Failed, "timed out");
        return;
    }
    if (s_state == State::Ready && !ctap::busy() && millis() - s_lastActivity > IDLE_TIMEOUT_MS) {
        stop("idle timeout");
        return;
    }

    size_t len = 0;
    int r = s_ws.poll(s_buf, sizeof(s_buf), &len);
    if (r < 0) {
        bool wasReady = s_state == State::Ready;
        stop("tunnel closed");
        if (!wasReady) setState(State::Failed, "tunnel closed");
        return;
    }
    if (r == 0) return;
    s_lastActivity = millis();

    if (s_state == State::Advertising) {
        uint8_t response[81];
        bool ok = respondToHandshake(s_buf, len, response);
        if (ok && !(ok = s_ws.sendBinary(response, sizeof(response)))) logf("HYBRID", "send response failed");
        if (ok && !(ok = sendPostHandshake())) logf("HYBRID", "send post-handshake failed");
        if (!ok) {
            stop("handshake failed");
            setState(State::Failed, "handshake failed");
            return;
        }
        ble::stopHybridAdvert();
        setState(State::Ready, "connected");
        return;
    }

    // Ready: [type][payload] after decryption and unpadding.
    static uint8_t pt[1200];
    int n = decrypt(s_buf, len, pt);
    if (n < 1) {
        stop("decrypt failed");
        return;
    }
    switch (pt[0]) {
        case kMsgShutdown:
            stop("PC finished");
            break;
        case kMsgCTAP:
            if (!ctap::submit(CtapTransport::Hybrid, pt + 1, (size_t)n - 1, ctapReply)) {
                uint8_t busy = CTAP1_ERR_CHANNEL_BUSY;
                ctapReply(&busy, 1);
            }
            break;
        case kMsgUpdate:
        default:
            break;   // linking updates are ignored
    }
}

State state() { return s_state; }
const char* stateText() { return s_status; }
const char* requestType() { return s_reqType; }

}  // namespace hybrid
