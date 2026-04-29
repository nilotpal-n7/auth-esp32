// =============================================================================
// fido2/ctap2.cpp — CTAP2 Command Handler (Core FIDO2 Logic)
// =============================================================================

#include "ctap2.h"
#include "crypto.h"
#include "ble_transport.h"
#include "../credential_store.h"
#include <string.h>

// =============================================================================
// INTERNAL STATE
// =============================================================================

static FidoPendingRequest s_pending;
static bool s_hasPending = false;

// Simplified CBOR helpers — for Phase 1 we use manual byte-level encoding
// A full CBOR library (like tinycbor) would be used in Phase 2.

// =============================================================================
// CBOR ENCODING HELPERS (minimal, hand-rolled)
// =============================================================================

static size_t cborEncodeUint8(uint8_t* buf, uint8_t val) {
    if (val <= 23) { buf[0] = val; return 1; }
    buf[0] = 0x18; buf[1] = val; return 2;
}

static size_t cborEncodeBytes(uint8_t* buf, const uint8_t* data, size_t len) {
    size_t pos = 0;
    if (len <= 23) {
        buf[pos++] = 0x40 | (uint8_t)len;
    } else if (len <= 255) {
        buf[pos++] = 0x58; buf[pos++] = (uint8_t)len;
    } else {
        buf[pos++] = 0x59;
        buf[pos++] = (uint8_t)(len >> 8);
        buf[pos++] = (uint8_t)(len & 0xFF);
    }
    memcpy(buf + pos, data, len);
    return pos + len;
}

static size_t cborEncodeText(uint8_t* buf, const char* str) {
    size_t len = strlen(str);
    size_t pos = 0;
    if (len <= 23) {
        buf[pos++] = 0x60 | (uint8_t)len;
    } else if (len <= 255) {
        buf[pos++] = 0x78; buf[pos++] = (uint8_t)len;
    } else {
        buf[pos++] = 0x79;
        buf[pos++] = (uint8_t)(len >> 8);
        buf[pos++] = (uint8_t)(len & 0xFF);
    }
    memcpy(buf + pos, str, len);
    return pos + len;
}

static size_t cborEncodeMapHeader(uint8_t* buf, uint8_t numPairs) {
    if (numPairs <= 23) { buf[0] = 0xA0 | numPairs; return 1; }
    buf[0] = 0xB8; buf[1] = numPairs; return 2;
}

static size_t cborEncodeNegInt(uint8_t* buf, int val) {
    // CBOR negative: -1-n encoded as major type 1
    uint8_t n = (uint8_t)(-(val + 1));
    if (n <= 23) { buf[0] = 0x20 | n; return 1; }
    buf[0] = 0x38; buf[1] = n; return 2;
}

// =============================================================================
// CBOR DECODING HELPERS (minimal — extract known fields)
// =============================================================================

// Skip a CBOR item and return bytes consumed. Very simplified.
static size_t cborSkipItem(const uint8_t* buf, size_t maxLen) {
    if (maxLen == 0) return 0;
    uint8_t major = buf[0] >> 5;
    uint8_t info = buf[0] & 0x1F;
    size_t headerLen = 1;
    uint64_t val = info;

    if (info == 24 && maxLen >= 2) { val = buf[1]; headerLen = 2; }
    else if (info == 25 && maxLen >= 3) { val = ((uint16_t)buf[1]<<8)|buf[2]; headerLen = 3; }

    switch (major) {
        case 0: case 1: return headerLen;  // uint/negint
        case 2: case 3: return headerLen + val;  // bytes/text
        case 4: {  // array
            size_t pos = headerLen;
            for (uint64_t i = 0; i < val && pos < maxLen; i++) pos += cborSkipItem(buf+pos, maxLen-pos);
            return pos;
        }
        case 5: {  // map
            size_t pos = headerLen;
            for (uint64_t i = 0; i < val*2 && pos < maxLen; i++) pos += cborSkipItem(buf+pos, maxLen-pos);
            return pos;
        }
        case 7: return 1;  // simple/float
        default: return 1;
    }
}

// Extract a text string value from a CBOR map by integer key
static bool cborExtractTextByIntKey(const uint8_t* map, size_t mapLen,
                                     uint8_t key, char* out, size_t outMax) {
    if (mapLen < 1) return false;
    uint8_t numPairs = map[0] & 0x1F;
    size_t pos = 1;
    for (uint8_t i = 0; i < numPairs && pos < mapLen; i++) {
        // Read key
        uint8_t k = map[pos]; pos++;
        // Read value
        if (k == key) {
            uint8_t vmajor = map[pos] >> 5;
            uint8_t vinfo = map[pos] & 0x1F;
            if (vmajor == 3) {  // text string
                size_t slen = vinfo;
                size_t hlen = 1;
                if (vinfo == 24) { slen = map[pos+1]; hlen = 2; }
                pos += hlen;
                size_t copyLen = (slen < outMax-1) ? slen : outMax-1;
                memcpy(out, map+pos, copyLen);
                out[copyLen] = '\0';
                return true;
            }
        }
        pos += cborSkipItem(map+pos, mapLen-pos);
    }
    return false;
}

// =============================================================================
// CTAP2 COMMAND: authenticatorGetInfo
// =============================================================================

static void handleGetInfo() {
    uint8_t resp[256];
    size_t pos = 0;

    // Status byte
    resp[pos++] = CTAP2_OK;

    // Response is a CBOR map
    pos += cborEncodeMapHeader(resp+pos, 6);

    // 0x01: versions (array of strings)
    pos += cborEncodeUint8(resp+pos, 0x01);
    resp[pos++] = 0x82;  // array(2)
    pos += cborEncodeText(resp+pos, "FIDO_2_0");
    pos += cborEncodeText(resp+pos, "U2F_V2");

    // 0x02: extensions (empty array)
    pos += cborEncodeUint8(resp+pos, 0x02);
    resp[pos++] = 0x80;  // array(0)

    // 0x03: aaguid (16 bytes — our device identifier)
    pos += cborEncodeUint8(resp+pos, 0x03);
    uint8_t aaguid[16] = {0xAA,0xBB,0xCC,0xDD,0x11,0x22,0x33,0x44,
                           0x55,0x66,0x77,0x88,0x99,0x00,0xAA,0xBB};
    pos += cborEncodeBytes(resp+pos, aaguid, 16);

    // 0x04: options map
    pos += cborEncodeUint8(resp+pos, 0x04);
    pos += cborEncodeMapHeader(resp+pos, 3);
    pos += cborEncodeText(resp+pos, "rk");
    resp[pos++] = 0xF5;  // true — resident keys supported
    pos += cborEncodeText(resp+pos, "up");
    resp[pos++] = 0xF5;  // true — user presence
    pos += cborEncodeText(resp+pos, "plat");
    resp[pos++] = 0xF4;  // false — not a platform authenticator

    // 0x05: maxMsgSize
    pos += cborEncodeUint8(resp+pos, 0x05);
    resp[pos++] = 0x19; resp[pos++] = 0x02; resp[pos++] = 0x00;  // 512

    // 0x06: pinUvAuthProtocols (empty — no PIN in Phase 1)
    pos += cborEncodeUint8(resp+pos, 0x06);
    resp[pos++] = 0x80;  // array(0)

    bleTransportSendResponse(resp, pos);
    Serial.printf("[CTAP2] GetInfo response sent (%d bytes)\n", pos);
}

// =============================================================================
// CTAP2 COMMAND: authenticatorMakeCredential
// =============================================================================

static void handleMakeCredential(const uint8_t* params, size_t paramsLen) {
    // Simplified CBOR parsing — extract rpId and clientDataHash
    // In a production build, use a proper CBOR library (tinycbor)

    // For Phase 1, we do simplified extraction:
    // The CBOR map keys are: 1=clientDataHash, 2=rp, 3=user, 4=pubKeyCredParams
    memset(&s_pending, 0, sizeof(s_pending));
    s_pending.type = FIDO_REQ_MAKE_CREDENTIAL;
    s_pending.timestampMs = millis();
    s_pending.approved = false;
    s_pending.processed = false;

    // Parse the outer map
    if (paramsLen < 2) { return; }
    size_t pos = 0;
    uint8_t numPairs = params[pos] & 0x1F;
    pos++;

    for (uint8_t i = 0; i < numPairs && pos < paramsLen; i++) {
        uint8_t key = params[pos++];

        if (key == 0x01) {
            // clientDataHash — 32-byte bstr
            uint8_t binfo = params[pos] & 0x1F;
            size_t blen = binfo;
            size_t hlen = 1;
            if (binfo == 24) { blen = params[pos+1]; hlen = 2; }
            pos += hlen;
            if (blen == 32) memcpy(s_pending.clientDataHash, params+pos, 32);
            pos += blen;
        } else if (key == 0x02) {
            // rp — map with "id" field
            cborExtractTextByIntKey(params+pos, paramsLen-pos, 0x02, s_pending.rpId, sizeof(s_pending.rpId));
            // Also try string key "id" — some clients use text keys
            if (s_pending.rpId[0] == '\0') {
                strncpy(s_pending.rpId, "unknown", sizeof(s_pending.rpId));
            }
            pos += cborSkipItem(params+pos, paramsLen-pos);
        } else if (key == 0x03) {
            // user — map with "name" and "id"
            cborExtractTextByIntKey(params+pos, paramsLen-pos, 0x02, s_pending.userName, sizeof(s_pending.userName));
            pos += cborSkipItem(params+pos, paramsLen-pos);
        } else {
            pos += cborSkipItem(params+pos, paramsLen-pos);
        }
    }

    if (s_pending.rpId[0] == '\0') strncpy(s_pending.rpId, "unknown.rp", sizeof(s_pending.rpId));
    if (s_pending.userName[0] == '\0') strncpy(s_pending.userName, "user", sizeof(s_pending.userName));

    s_hasPending = true;
    Serial.printf("[CTAP2] MakeCredential request for RP: %s, User: %s\n",
                  s_pending.rpId, s_pending.userName);
}

static void completeMakeCredential() {
    // Generate a new keypair
    uint8_t pubKey[65]; size_t pubLen = sizeof(pubKey);
    uint8_t privKey[32]; size_t privLen = sizeof(privKey);

    if (!cryptoGenerateKeyPair(pubKey, &pubLen, privKey, &privLen)) {
        uint8_t err[1] = { CTAP2_ERR_OPERATION_DENIED };
        bleTransportSendResponse(err, 1);
        return;
    }

    // Generate random credential ID
    uint8_t credId[FIDO2_CRED_ID_LEN];
    cryptoRandom(credId, sizeof(credId));

    // Store credential in NVS
    FidoCredential cred;
    memset(&cred, 0, sizeof(cred));
    memcpy(cred.credentialId, credId, FIDO2_CRED_ID_LEN);
    memcpy(cred.privateKey, privKey, FIDO2_PRIVKEY_LEN);
    memcpy(cred.publicKey, pubKey, pubLen);
    strncpy(cred.rpId, s_pending.rpId, FIDO2_RP_ID_MAX_LEN - 1);
    strncpy(cred.userName, s_pending.userName, FIDO2_USER_NAME_MAX_LEN - 1);
    if (s_pending.userIdLen > 0) {
        memcpy(cred.userId, s_pending.userId, s_pending.userIdLen);
        cred.userIdLen = s_pending.userIdLen;
    }
    cred.signCounter = 0;
    cred.valid = true;

    if (credStoreSaveFido(&cred) < 0) {
        uint8_t err[1] = { CTAP2_ERR_KEY_STORE_FULL };
        bleTransportSendResponse(err, 1);
        return;
    }

    // Build attestation response
    // authData = rpIdHash(32) + flags(1) + signCount(4) + attestedCredData
    uint8_t authData[256];
    size_t adPos = 0;

    // rpIdHash
    uint8_t rpIdHash[32];
    cryptoSHA256((const uint8_t*)s_pending.rpId, strlen(s_pending.rpId), rpIdHash);
    memcpy(authData + adPos, rpIdHash, 32); adPos += 32;

    // flags: UP(0x01) | AT(0x40) = 0x41
    authData[adPos++] = 0x41;

    // signCounter (4 bytes big-endian)
    authData[adPos++] = 0; authData[adPos++] = 0;
    authData[adPos++] = 0; authData[adPos++] = 0;

    // Attested credential data: AAGUID(16) + credIdLen(2) + credId + pubKeyCOSE
    uint8_t aaguid[16] = {0xAA,0xBB,0xCC,0xDD,0x11,0x22,0x33,0x44,
                           0x55,0x66,0x77,0x88,0x99,0x00,0xAA,0xBB};
    memcpy(authData + adPos, aaguid, 16); adPos += 16;
    authData[adPos++] = 0; authData[adPos++] = FIDO2_CRED_ID_LEN;
    memcpy(authData + adPos, credId, FIDO2_CRED_ID_LEN); adPos += FIDO2_CRED_ID_LEN;

    // COSE public key (EC2, P-256): map of 5 pairs
    authData[adPos++] = 0xA5;  // map(5)
    // 1: kty = 2 (EC2)
    adPos += cborEncodeUint8(authData+adPos, 1);
    adPos += cborEncodeUint8(authData+adPos, 2);
    // 3: alg = -7 (ES256)
    adPos += cborEncodeUint8(authData+adPos, 3);
    adPos += cborEncodeNegInt(authData+adPos, -7);
    // -1: crv = 1 (P-256)
    adPos += cborEncodeNegInt(authData+adPos, -1);
    adPos += cborEncodeUint8(authData+adPos, 1);
    // -2: x coordinate (32 bytes)
    adPos += cborEncodeNegInt(authData+adPos, -2);
    adPos += cborEncodeBytes(authData+adPos, pubKey + 1, 32);
    // -3: y coordinate (32 bytes)
    adPos += cborEncodeNegInt(authData+adPos, -3);
    adPos += cborEncodeBytes(authData+adPos, pubKey + 33, 32);

    // Build full response: status + CBOR map {1:fmt, 2:authData, 3:attStmt}
    uint8_t resp[512];
    size_t rPos = 0;
    resp[rPos++] = CTAP2_OK;
    rPos += cborEncodeMapHeader(resp+rPos, 3);

    // 1: fmt = "packed"
    rPos += cborEncodeUint8(resp+rPos, 1);
    rPos += cborEncodeText(resp+rPos, "packed");

    // 2: authData
    rPos += cborEncodeUint8(resp+rPos, 2);
    rPos += cborEncodeBytes(resp+rPos, authData, adPos);

    // 3: attStmt = {} (self-attestation, empty map for Phase 1)
    rPos += cborEncodeUint8(resp+rPos, 3);
    resp[rPos++] = 0xA0;  // empty map

    bleTransportSendResponse(resp, rPos);
    Serial.printf("[CTAP2] MakeCredential complete. Response: %d bytes\n", rPos);
}

// =============================================================================
// CTAP2 COMMAND: authenticatorGetAssertion
// =============================================================================

static void handleGetAssertion(const uint8_t* params, size_t paramsLen) {
    memset(&s_pending, 0, sizeof(s_pending));
    s_pending.type = FIDO_REQ_GET_ASSERTION;
    s_pending.timestampMs = millis();
    s_pending.approved = false;
    s_pending.processed = false;

    // Parse: 1=rpId(text), 2=clientDataHash(bstr)
    size_t pos = 0;
    if (paramsLen < 2) return;
    uint8_t numPairs = params[pos] & 0x1F;
    pos++;

    for (uint8_t i = 0; i < numPairs && pos < paramsLen; i++) {
        uint8_t key = params[pos++];
        if (key == 0x01) {
            // rpId — text string
            uint8_t info = params[pos] & 0x1F;
            size_t slen = info; size_t hlen = 1;
            if (info == 24) { slen = params[pos+1]; hlen = 2; }
            pos += hlen;
            size_t copyLen = (slen < sizeof(s_pending.rpId)-1) ? slen : sizeof(s_pending.rpId)-1;
            memcpy(s_pending.rpId, params+pos, copyLen);
            s_pending.rpId[copyLen] = '\0';
            pos += slen;
        } else if (key == 0x02) {
            uint8_t binfo = params[pos] & 0x1F;
            size_t blen = binfo; size_t hlen = 1;
            if (binfo == 24) { blen = params[pos+1]; hlen = 2; }
            pos += hlen;
            if (blen == 32) memcpy(s_pending.clientDataHash, params+pos, 32);
            pos += blen;
        } else {
            pos += cborSkipItem(params+pos, paramsLen-pos);
        }
    }

    if (s_pending.rpId[0] == '\0') strncpy(s_pending.rpId, "unknown.rp", sizeof(s_pending.rpId));

    s_hasPending = true;
    Serial.printf("[CTAP2] GetAssertion request for RP: %s\n", s_pending.rpId);
}

static void completeGetAssertion() {
    // Lookup credential by RP ID
    FidoCredential cred;
    if (!credStoreFindByRpId(s_pending.rpId, &cred)) {
        uint8_t err[1] = { CTAP2_ERR_NO_CREDENTIALS };
        bleTransportSendResponse(err, 1);
        Serial.println("[CTAP2] No credential found for this RP.");
        return;
    }

    // Increment sign counter
    uint32_t counter = credStoreIncrementCounter(cred.credentialId);

    // Build authenticator data
    uint8_t authData[64];
    size_t adPos = 0;

    uint8_t rpIdHash[32];
    cryptoSHA256((const uint8_t*)s_pending.rpId, strlen(s_pending.rpId), rpIdHash);
    memcpy(authData + adPos, rpIdHash, 32); adPos += 32;

    // flags: UP(0x01) = 0x01
    authData[adPos++] = 0x01;

    // signCounter (4 bytes big-endian)
    authData[adPos++] = (uint8_t)(counter >> 24);
    authData[adPos++] = (uint8_t)(counter >> 16);
    authData[adPos++] = (uint8_t)(counter >> 8);
    authData[adPos++] = (uint8_t)(counter);

    // Sign: SHA-256(authData || clientDataHash)
    uint8_t signInput[128];
    memcpy(signInput, authData, adPos);
    memcpy(signInput + adPos, s_pending.clientDataHash, 32);

    uint8_t signHash[32];
    cryptoSHA256(signInput, adPos + 32, signHash);

    uint8_t signature[80];
    size_t sigLen = sizeof(signature);
    if (!cryptoSign(signHash, 32, cred.privateKey, FIDO2_PRIVKEY_LEN, signature, &sigLen)) {
        uint8_t err[1] = { CTAP2_ERR_OPERATION_DENIED };
        bleTransportSendResponse(err, 1);
        return;
    }

    // Build response: {1:credential, 2:authData, 3:signature}
    uint8_t resp[384];
    size_t rPos = 0;
    resp[rPos++] = CTAP2_OK;
    rPos += cborEncodeMapHeader(resp+rPos, 3);

    // 1: credential {type:"public-key", id:credId}
    rPos += cborEncodeUint8(resp+rPos, 1);
    rPos += cborEncodeMapHeader(resp+rPos, 2);
    rPos += cborEncodeText(resp+rPos, "type");
    rPos += cborEncodeText(resp+rPos, "public-key");
    rPos += cborEncodeText(resp+rPos, "id");
    rPos += cborEncodeBytes(resp+rPos, cred.credentialId, FIDO2_CRED_ID_LEN);

    // 2: authData
    rPos += cborEncodeUint8(resp+rPos, 2);
    rPos += cborEncodeBytes(resp+rPos, authData, adPos);

    // 3: signature
    rPos += cborEncodeUint8(resp+rPos, 3);
    rPos += cborEncodeBytes(resp+rPos, signature, sigLen);

    bleTransportSendResponse(resp, rPos);
    Serial.printf("[CTAP2] GetAssertion complete. Signature: %d bytes\n", sigLen);
}

// =============================================================================
// PUBLIC API
// =============================================================================

void ctap2Init() {
    memset(&s_pending, 0, sizeof(s_pending));
    s_hasPending = false;
    Serial.println("[CTAP2] Handler initialized.");
}

void ctap2ProcessCommand(const uint8_t* data, size_t len) {
    if (len < 1) return;

    uint8_t cmd = data[0];
    const uint8_t* params = data + 1;
    size_t paramsLen = len - 1;

    Serial.printf("[CTAP2] Command: 0x%02X (%d bytes)\n", cmd, len);

    switch (cmd) {
        case CTAP2_CMD_GET_INFO:
            handleGetInfo();
            break;
        case CTAP2_CMD_MAKE_CREDENTIAL:
            handleMakeCredential(params, paramsLen);
            break;
        case CTAP2_CMD_GET_ASSERTION:
            handleGetAssertion(params, paramsLen);
            break;
        default:
            Serial.printf("[CTAP2] Unsupported command: 0x%02X\n", cmd);
            uint8_t err[1] = { CTAP2_ERR_CBOR_UNEXPECTED };
            bleTransportSendResponse(err, 1);
            break;
    }
}

FidoPendingRequest* ctap2GetPendingRequest() {
    if (s_hasPending && !s_pending.processed) return &s_pending;
    return nullptr;
}

void ctap2ApproveRequest() {
    if (!s_hasPending) return;
    s_pending.approved = true;

    if (s_pending.type == FIDO_REQ_MAKE_CREDENTIAL) {
        completeMakeCredential();
    } else if (s_pending.type == FIDO_REQ_GET_ASSERTION) {
        completeGetAssertion();
    }

    s_pending.processed = true;
    s_hasPending = false;
}

void ctap2DenyRequest() {
    if (!s_hasPending) return;
    uint8_t err[1] = { CTAP2_ERR_OPERATION_DENIED };
    bleTransportSendResponse(err, 1);
    s_pending.processed = true;
    s_hasPending = false;
    Serial.println("[CTAP2] Request denied (timeout or user rejection).");
}
