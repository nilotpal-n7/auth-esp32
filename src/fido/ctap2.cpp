#include "fido/ctap2.h"
#include "fido/credentials.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "util/cbor.h"

namespace ctap {

#define CMD_MAKE_CREDENTIAL     0x01
#define CMD_GET_ASSERTION       0x02
#define CMD_GET_INFO            0x04
#define CMD_CLIENT_PIN          0x06
#define CMD_RESET               0x07
#define CMD_GET_NEXT_ASSERTION  0x08
#define CMD_SELECTION           0x0B

#define FLAG_UP 0x01
#define FLAG_UV 0x04
#define FLAG_AT 0x40

#define COSE_ES256 (-7)
#define MAX_ACCOUNTS 8
#define NEXT_ASSERTION_TIMEOUT_MS 30000

// Random, fixed AAGUID identifying this authenticator model.
static const uint8_t AAGUID[16] = {
    0x6c, 0x1f, 0x3e, 0x9a, 0x45, 0x0b, 0x4e, 0x2d,
    0x9f, 0x31, 0x7a, 0xc2, 0x58, 0xe4, 0x10, 0xb7,
};

// --- Pending request state ---------------------------------------------------

struct Request {
    uint8_t  cmd;
    uint8_t  cdh[32];
    uint8_t  rpIdHash[32];
    char     rpId[RP_ID_MAX];
    uint8_t  userId[USER_ID_MAX];
    uint8_t  userIdLen;
    char     userName[USER_NAME_MAX];
    char     displayName[USER_NAME_MAX];
    bool     rk;
    bool     up;
    bool     uv;
    bool     excluded;
    bool     selectOnly;       // empty pinAuth "touch to select"
    // Assertion candidates
    bool     haveAllowed;
    uint8_t  allowedId[CRED_ID_LEN];
    int      slots[MAX_ACCOUNTS];
    int      slotCount;
};

static Request       s_req;
static bool          s_pending = false;
static bool          s_uvDone = false;
static CtapTransport s_transport;
static CtapReplyFn   s_reply = nullptr;
static CtapPrompt    s_prompt;

// getNextAssertion continuation
static struct {
    bool          active;
    CtapTransport transport;
    int           index;
    uint32_t      lastMs;
    uint8_t       flags;
} s_next;

static uint8_t s_out[FIDO_MAX_MSG];

// --- Helpers -----------------------------------------------------------------

static void replyStatus(CtapReplyFn reply, uint8_t status) {
    reply(&status, 1);
}

static void finishPending(uint8_t status, size_t len) {
    // `s_out[0]` holds the status for successful responses with a body.
    CtapReplyFn reply = s_reply;
    s_pending = false;
    s_prompt.kind = PromptKind::None;
    s_uvDone = false;
    if (!reply) return;
    if (status != CTAP2_OK || len == 0) replyStatus(reply, status);
    else reply(s_out, len);
}

#define EXPECT(r, major) \
    do { if ((r).peekMajor() != (major)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE; } while (0)
#define CHECK_CBOR(r) \
    do { if (!(r).ok()) return CTAP2_ERR_INVALID_CBOR; } while (0)

static uint8_t readRpId(CborReader& r, Request& q) {
    const char* s; size_t n;
    EXPECT(r, CBOR_TEXT);
    if (!r.readText(&s, &n)) return CTAP2_ERR_INVALID_CBOR;
    crypto::sha256((const uint8_t*)s, n, q.rpIdHash);
    size_t c = n < sizeof(q.rpId) - 1 ? n : sizeof(q.rpId) - 1;
    memcpy(q.rpId, s, c);
    q.rpId[c] = '\0';
    return CTAP2_OK;
}

static uint8_t parseRp(CborReader& r, Request& q, bool* haveId) {
    size_t n;
    EXPECT(r, CBOR_MAP);
    r.readMap(&n);
    for (size_t i = 0; i < n; i++) {
        bool isId = false;
        EXPECT(r, CBOR_TEXT);
        r.readTextEquals("id", &isId);
        if (isId) {
            uint8_t st = readRpId(r, q);
            if (st) return st;
            *haveId = true;
        } else {
            r.skip();
        }
        CHECK_CBOR(r);
    }
    return CTAP2_OK;
}

static uint8_t parseUser(CborReader& r, Request& q, bool* haveId) {
    size_t n;
    EXPECT(r, CBOR_MAP);
    r.readMap(&n);
    for (size_t i = 0; i < n; i++) {
        const char* k; size_t kl;
        EXPECT(r, CBOR_TEXT);
        r.readText(&k, &kl);
        if (kl == 2 && !memcmp(k, "id", 2)) {
            const uint8_t* p; size_t pl;
            EXPECT(r, CBOR_BYTES);
            r.readBytes(&p, &pl);
            if (pl > USER_ID_MAX) return CTAP1_ERR_INVALID_LENGTH;
            memcpy(q.userId, p, pl);
            q.userIdLen = (uint8_t)pl;
            *haveId = true;
        } else if (kl == 4 && !memcmp(k, "name", 4)) {
            EXPECT(r, CBOR_TEXT);
            r.readTextInto(q.userName, sizeof(q.userName));
        } else if (kl == 11 && !memcmp(k, "displayName", 11)) {
            EXPECT(r, CBOR_TEXT);
            r.readTextInto(q.displayName, sizeof(q.displayName));
        } else {
            r.skip();
        }
        CHECK_CBOR(r);
    }
    return CTAP2_OK;
}

static uint8_t parsePubKeyParams(CborReader& r, bool* es256) {
    size_t n;
    EXPECT(r, CBOR_ARRAY);
    r.readArray(&n);
    for (size_t i = 0; i < n; i++) {
        size_t m;
        EXPECT(r, CBOR_MAP);
        r.readMap(&m);
        int64_t alg = 0;
        bool haveAlg = false, isPublicKey = false;
        for (size_t j = 0; j < m; j++) {
            const char* k; size_t kl;
            EXPECT(r, CBOR_TEXT);
            r.readText(&k, &kl);
            if (kl == 3 && !memcmp(k, "alg", 3)) {
                if (r.peekMajor() != CBOR_UINT && r.peekMajor() != CBOR_NINT)
                    return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
                r.readInt(&alg);
                haveAlg = true;
            } else if (kl == 4 && !memcmp(k, "type", 4)) {
                EXPECT(r, CBOR_TEXT);
                r.readTextEquals("public-key", &isPublicKey);
            } else {
                r.skip();
            }
            CHECK_CBOR(r);
        }
        if (!haveAlg) return CTAP2_ERR_MISSING_PARAMETER;
        if (isPublicKey && alg == COSE_ES256) *es256 = true;
    }
    return CTAP2_OK;
}

// Walk a list of PublicKeyCredentialDescriptors. Stores the first ID that this
// device issued for the request's RP in q.allowedId.
static uint8_t parseCredList(CborReader& r, Request& q, bool* found) {
    size_t n;
    EXPECT(r, CBOR_ARRAY);
    r.readArray(&n);
    for (size_t i = 0; i < n; i++) {
        size_t m;
        EXPECT(r, CBOR_MAP);
        r.readMap(&m);
        const uint8_t* id = nullptr; size_t idLen = 0;
        bool isPublicKey = false, haveType = false;
        for (size_t j = 0; j < m; j++) {
            const char* k; size_t kl;
            EXPECT(r, CBOR_TEXT);
            r.readText(&k, &kl);
            if (kl == 2 && !memcmp(k, "id", 2)) {
                EXPECT(r, CBOR_BYTES);
                r.readBytes(&id, &idLen);
            } else if (kl == 4 && !memcmp(k, "type", 4)) {
                EXPECT(r, CBOR_TEXT);
                r.readTextEquals("public-key", &isPublicKey);
                haveType = true;
            } else {
                r.skip();
            }
            CHECK_CBOR(r);
        }
        if (!id || !haveType) return CTAP2_ERR_MISSING_PARAMETER;
        if (!*found && isPublicKey) {
            uint8_t priv[32];
            if (creds::derive(id, idLen, q.rpIdHash, priv)) {
                memcpy(q.allowedId, id, CRED_ID_LEN);
                *found = true;
            }
            crypto::wipe(priv, sizeof(priv));
        }
    }
    return CTAP2_OK;
}

static uint8_t parseOptions(CborReader& r, Request& q, bool allowRk, bool allowUp) {
    size_t n;
    EXPECT(r, CBOR_MAP);
    r.readMap(&n);
    for (size_t i = 0; i < n; i++) {
        const char* k; size_t kl;
        bool v = false;
        EXPECT(r, CBOR_TEXT);
        r.readText(&k, &kl);
        if (r.peekMajor() != CBOR_SIMPLE) { r.skip(); CHECK_CBOR(r); continue; }
        if (!r.readBool(&v)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        if (kl == 2 && !memcmp(k, "rk", 2)) {
            if (!allowRk && v) return CTAP2_ERR_UNSUPPORTED_OPTION;
            q.rk = v;
        } else if (kl == 2 && !memcmp(k, "uv", 2)) {
            q.uv = v;
        } else if (kl == 2 && !memcmp(k, "up", 2)) {
            if (!allowUp && !v) return CTAP2_ERR_INVALID_OPTION;
            q.up = v;
        }
    }
    return CTAP2_OK;
}

static uint8_t checkUvAvailable() {
    if (!settings::pinIsSet()) return CTAP2_ERR_UNSUPPORTED_OPTION;
    if (settings::pinRetries() == 0) return CTAP2_ERR_PIN_BLOCKED;
    return CTAP2_OK;
}

static void writeCounter(uint8_t* p, uint32_t c) {
    p[0] = c >> 24; p[1] = c >> 16; p[2] = c >> 8; p[3] = c;
}

// --- authenticatorGetInfo ----------------------------------------------------

size_t buildGetInfo(uint8_t* out, size_t cap) {
    CborWriter w(out, cap);
    w.map(6);
    w.uint(0x01);                       // versions
    w.array(1);
    w.text("FIDO_2_0");
    w.uint(0x03);                       // aaguid
    w.bytes(AAGUID, sizeof(AAGUID));
    // "uv" is only advertised once a device PIN exists: reporting it as
    // supported-but-unconfigured makes Windows and other clients demand that
    // the user configure UV before any UV-preferred request.
    bool uv = settings::pinIsSet();
    w.uint(0x04);                       // options
    w.map(uv ? 4 : 3);
    w.text("rk");   w.boolean(true);
    w.text("up");   w.boolean(true);
    if (uv) { w.text("uv"); w.boolean(true); }   // built-in PIN entry on the device
    w.text("plat"); w.boolean(false);
    w.uint(0x05);                       // maxMsgSize
    w.uint(FIDO_MAX_MSG);
    w.uint(0x09);                      // transports
    w.array(2);
    w.text("ble");
    w.text("hybrid");
    w.uint(0x0A);                       // algorithms
    w.array(1);
    w.map(2);
    w.text("alg");  w.integer(COSE_ES256);
    w.text("type"); w.text("public-key");
    return w.ok() ? w.size() : 0;
}

static void handleGetInfo(CtapReplyFn reply) {
    s_out[0] = CTAP2_OK;
    size_t n = buildGetInfo(s_out + 1, sizeof(s_out) - 1);
    if (n == 0) { replyStatus(reply, CTAP1_ERR_OTHER); return; }
    reply(s_out, n + 1);
}

// --- authenticatorMakeCredential ---------------------------------------------

static uint8_t parseMakeCredential(const uint8_t* p, size_t len, Request& q) {
    CborReader r(p, len);
    size_t n;
    EXPECT(r, CBOR_MAP);
    r.readMap(&n);
    bool haveCdh = false, haveRp = false, haveUser = false, haveParams = false, es256 = false;
    q.up = true;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        EXPECT(r, CBOR_UINT);
        r.readUint(&key);
        uint8_t st = CTAP2_OK;
        switch (key) {
            case 0x01: {
                const uint8_t* d; size_t dl;
                EXPECT(r, CBOR_BYTES);
                r.readBytes(&d, &dl);
                if (dl != 32) return CTAP1_ERR_INVALID_LENGTH;
                memcpy(q.cdh, d, 32);
                haveCdh = true;
                break;
            }
            case 0x02: st = parseRp(r, q, &haveRp); break;
            case 0x03: st = parseUser(r, q, &haveUser); break;
            case 0x04: st = parsePubKeyParams(r, &es256); haveParams = true; break;
            case 0x05:
                // The RP hash is needed to check exclusions; key 2 always
                // precedes key 5 in canonical CBOR.
                if (!haveRp) return CTAP2_ERR_MISSING_PARAMETER;
                st = parseCredList(r, q, &q.excluded);
                break;
            case 0x07: st = parseOptions(r, q, true, false); break;
            case 0x08: {
                const uint8_t* d; size_t dl;
                EXPECT(r, CBOR_BYTES);
                r.readBytes(&d, &dl);
                if (dl == 0) q.selectOnly = true;
                else st = CTAP2_ERR_PIN_AUTH_INVALID;   // no clientPin protocol
                break;
            }
            default: r.skip(); break;    // extensions, pinProtocol, ...
        }
        if (st) return st;
        CHECK_CBOR(r);
    }
    if (!haveCdh || !haveRp || !haveUser || !haveParams) return CTAP2_ERR_MISSING_PARAMETER;
    if (!es256) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    return CTAP2_OK;
}

static size_t completeMakeCredential(uint8_t* status) {
    Request& q = s_req;
    if (q.excluded) { *status = CTAP2_ERR_CREDENTIAL_EXCLUDED; return 0; }

    uint8_t credId[CRED_ID_LEN], pub[65], priv[32];
    if (!creds::create(q.rpIdHash, q.rk, credId, pub, priv)) {
        *status = CTAP1_ERR_OTHER;
        return 0;
    }
    if (q.rk) {
        ResidentCredential rc;
        memset(&rc, 0, sizeof(rc));
        memcpy(rc.credId, credId, CRED_ID_LEN);
        memcpy(rc.rpIdHash, q.rpIdHash, 32);
        strlcpy(rc.rpId, q.rpId, sizeof(rc.rpId));
        memcpy(rc.userId, q.userId, q.userIdLen);
        rc.userIdLen = q.userIdLen;
        strlcpy(rc.userName, q.userName, sizeof(rc.userName));
        strlcpy(rc.displayName, q.displayName, sizeof(rc.displayName));
        if (!creds::residentPut(rc)) {
            crypto::wipe(priv, sizeof(priv));
            *status = CTAP2_ERR_KEY_STORE_FULL;
            return 0;
        }
    }

    // authData = rpIdHash | flags | signCount | AAGUID | len | credId | COSE key
    uint8_t authData[256];
    size_t a = 0;
    memcpy(authData, q.rpIdHash, 32); a += 32;
    authData[a++] = FLAG_UP | FLAG_AT | (s_uvDone ? FLAG_UV : 0);
    writeCounter(authData + a, settings::nextSignCount()); a += 4;
    memcpy(authData + a, AAGUID, 16); a += 16;
    authData[a++] = 0;
    authData[a++] = CRED_ID_LEN;
    memcpy(authData + a, credId, CRED_ID_LEN); a += CRED_ID_LEN;
    CborWriter cose(authData + a, sizeof(authData) - a);
    cose.map(5);
    cose.uint(1);      cose.uint(2);            // kty: EC2
    cose.uint(3);      cose.integer(COSE_ES256);// alg
    cose.integer(-1);  cose.uint(1);            // crv: P-256
    cose.integer(-2);  cose.bytes(pub + 1, 32); // x
    cose.integer(-3);  cose.bytes(pub + 33, 32);// y
    a += cose.size();

    // Packed self-attestation: sign authData || clientDataHash with the new key.
    crypto::Sha256 h;
    h.update(authData, a);
    h.update(q.cdh, 32);
    uint8_t digest[32], sig[80];
    size_t sigLen = sizeof(sig);
    h.finish(digest);
    bool signedOk = crypto::p256Sign(priv, digest, sig, &sigLen);
    crypto::wipe(priv, sizeof(priv));
    if (!signedOk) { *status = CTAP1_ERR_OTHER; return 0; }

    s_out[0] = CTAP2_OK;
    CborWriter w(s_out + 1, sizeof(s_out) - 1);
    w.map(3);
    w.uint(1); w.text("packed");
    w.uint(2); w.bytes(authData, a);
    w.uint(3); w.map(2);
    w.text("alg"); w.integer(COSE_ES256);
    w.text("sig"); w.bytes(sig, sigLen);
    if (!w.ok()) { *status = CTAP2_ERR_REQUEST_TOO_LARGE; return 0; }
    *status = CTAP2_OK;
    logEvent("Registered %s", q.rpId);
    return w.size() + 1;
}

// --- authenticatorGetAssertion -----------------------------------------------

static uint8_t parseGetAssertion(const uint8_t* p, size_t len, Request& q) {
    CborReader r(p, len);
    size_t n;
    EXPECT(r, CBOR_MAP);
    r.readMap(&n);
    bool haveRp = false, haveCdh = false, haveAllowList = false;
    q.up = true;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        EXPECT(r, CBOR_UINT);
        r.readUint(&key);
        uint8_t st = CTAP2_OK;
        switch (key) {
            case 0x01: st = readRpId(r, q); haveRp = true; break;
            case 0x02: {
                const uint8_t* d; size_t dl;
                EXPECT(r, CBOR_BYTES);
                r.readBytes(&d, &dl);
                if (dl != 32) return CTAP1_ERR_INVALID_LENGTH;
                memcpy(q.cdh, d, 32);
                haveCdh = true;
                break;
            }
            case 0x03:
                if (!haveRp) return CTAP2_ERR_MISSING_PARAMETER;
                st = parseCredList(r, q, &q.haveAllowed);
                haveAllowList = true;
                break;
            case 0x05: st = parseOptions(r, q, false, true); break;
            case 0x06: {
                const uint8_t* d; size_t dl;
                EXPECT(r, CBOR_BYTES);
                r.readBytes(&d, &dl);
                if (dl == 0) q.selectOnly = true;
                else st = CTAP2_ERR_PIN_AUTH_INVALID;
                break;
            }
            default: r.skip(); break;
        }
        if (st) return st;
        CHECK_CBOR(r);
    }
    if (!haveRp || !haveCdh) return CTAP2_ERR_MISSING_PARAMETER;
    if (!haveAllowList) {
        q.slotCount = creds::residentFind(q.rpIdHash, q.slots, MAX_ACCOUNTS);
    }
    return CTAP2_OK;
}

// Build one assertion. `index` selects the discoverable account (ignored when
// an allowList matched). `first` adds numberOfCredentials when > 1.
static size_t buildAssertion(int index, bool first, uint8_t flags, uint8_t* status) {
    Request& q = s_req;
    uint8_t credId[CRED_ID_LEN];
    ResidentCredential rc;
    bool resident = false;
    if (q.haveAllowed) {
        memcpy(credId, q.allowedId, CRED_ID_LEN);
    } else {
        if (index >= q.slotCount || !creds::residentGet(q.slots[index], &rc)) {
            *status = CTAP2_ERR_NO_CREDENTIALS;
            return 0;
        }
        memcpy(credId, rc.credId, CRED_ID_LEN);
        resident = true;
    }

    uint8_t priv[32];
    if (!creds::derive(credId, CRED_ID_LEN, q.rpIdHash, priv)) {
        *status = CTAP2_ERR_NO_CREDENTIALS;
        return 0;
    }

    uint8_t authData[37];
    memcpy(authData, q.rpIdHash, 32);
    authData[32] = flags;
    writeCounter(authData + 33, settings::nextSignCount());

    crypto::Sha256 h;
    h.update(authData, sizeof(authData));
    h.update(q.cdh, 32);
    uint8_t digest[32], sig[80];
    size_t sigLen = sizeof(sig);
    h.finish(digest);
    bool signedOk = crypto::p256Sign(priv, digest, sig, &sigLen);
    crypto::wipe(priv, sizeof(priv));
    if (!signedOk) { *status = CTAP1_ERR_OTHER; return 0; }

    bool numCreds = first && !q.haveAllowed && q.slotCount > 1;
    // User identifiable info only after user verification (CTAP2 §5.2).
    bool userDetails = resident && (flags & FLAG_UV);

    s_out[0] = CTAP2_OK;
    CborWriter w(s_out + 1, sizeof(s_out) - 1);
    w.map(3 + (resident ? 1 : 0) + (numCreds ? 1 : 0));
    w.uint(1);
    w.map(2);
    w.text("id");   w.bytes(credId, CRED_ID_LEN);
    w.text("type"); w.text("public-key");
    w.uint(2); w.bytes(authData, sizeof(authData));
    w.uint(3); w.bytes(sig, sigLen);
    if (resident) {
        w.uint(4);
        bool hasName = userDetails && rc.userName[0];
        bool hasDisplay = userDetails && rc.displayName[0];
        w.map(1 + hasName + hasDisplay);
        w.text("id"); w.bytes(rc.userId, rc.userIdLen);
        if (hasName)    { w.text("name");        w.text(rc.userName); }
        if (hasDisplay) { w.text("displayName"); w.text(rc.displayName); }
    }
    if (numCreds) { w.uint(5); w.uint(q.slotCount); }
    if (!w.ok()) { *status = CTAP1_ERR_OTHER; return 0; }
    *status = CTAP2_OK;
    return w.size() + 1;
}

static size_t completeGetAssertion(uint8_t* status) {
    Request& q = s_req;
    uint8_t flags = (q.up ? FLAG_UP : 0) | (s_uvDone ? FLAG_UV : 0);
    size_t n = buildAssertion(0, true, flags, status);
    if (*status == CTAP2_OK) {
        s_next.active = !q.haveAllowed && q.slotCount > 1;
        s_next.transport = s_transport;
        s_next.index = 1;
        s_next.lastMs = millis();
        s_next.flags = flags;
        if (q.up) logEvent("Signed in %s", q.rpId);
    }
    return n;
}

static void handleGetNextAssertion(CtapTransport t, CtapReplyFn reply) {
    if (!s_next.active || s_next.transport != t ||
        millis() - s_next.lastMs > NEXT_ASSERTION_TIMEOUT_MS ||
        s_next.index >= s_req.slotCount) {
        s_next.active = false;
        replyStatus(reply, CTAP2_ERR_NOT_ALLOWED);
        return;
    }
    uint8_t status;
    size_t n = buildAssertion(s_next.index++, false, s_next.flags, &status);
    s_next.lastMs = millis();
    if (status != CTAP2_OK) replyStatus(reply, status);
    else reply(s_out, n);
}

// --- Prompt / completion -----------------------------------------------------

static void startPrompt(PromptKind kind) {
    memset(&s_prompt, 0, sizeof(s_prompt));
    s_prompt.kind = kind;
    s_prompt.transport = s_transport;
    strlcpy(s_prompt.rpId, s_req.rpId, sizeof(s_prompt.rpId));
    const char* user = s_req.userName[0] ? s_req.userName : s_req.displayName;
    strlcpy(s_prompt.userName, user, sizeof(s_prompt.userName));
    s_prompt.needPin = s_req.uv && !s_uvDone;
    s_prompt.excluded = s_req.excluded;
    s_prompt.accountCount = s_req.haveAllowed ? 1 : s_req.slotCount;
    s_prompt.startedMs = millis();
    s_pending = true;
}

static void complete() {
    uint8_t status = CTAP2_OK;
    size_t n = 0;
    if (s_req.selectOnly) {
        status = settings::pinIsSet() ? CTAP2_ERR_PIN_INVALID : CTAP2_ERR_PIN_NOT_SET;
    } else {
        switch (s_req.cmd) {
            case CMD_MAKE_CREDENTIAL: n = completeMakeCredential(&status); break;
            case CMD_GET_ASSERTION:   n = completeGetAssertion(&status); break;
            case CMD_RESET:
                settings::resetFido();
                creds::residentWipe();
                logEvent("FIDO reset");
                break;
            case CMD_SELECTION: break;
        }
    }
    finishPending(status, n);
}

void userApprove() {
    if (!s_pending) return;
    if (s_prompt.needPin) return;       // must enter PIN first
    complete();
}

void userDeny() {
    if (!s_pending) return;
    logEvent("Denied %s", s_prompt.rpId);
    finishPending(CTAP2_ERR_OPERATION_DENIED, 0);
}

bool userSubmitPin(const char* pin) {
    if (!s_pending || !s_prompt.needPin) return false;
    if (settings::pinVerify(pin)) {
        settings::uvSessionStart();     // stay unlocked for the session window
        s_uvDone = true;
        s_prompt.needPin = false;
        complete();                     // PIN entry is also proof of presence
        return true;
    }
    if (settings::pinRetries() == 0) {
        logEvent("PIN blocked");
        finishPending(CTAP2_ERR_PIN_BLOCKED, 0);
    }
    return false;
}

const CtapPrompt* prompt() { return s_pending ? &s_prompt : nullptr; }
bool busy() { return s_pending; }
CtapTransport busyTransport() { return s_transport; }

void cancel(CtapTransport t) {
    if (s_pending && s_transport == t) {
        logf("CTAP", "Request cancelled by client");
        finishPending(CTAP2_ERR_KEEPALIVE_CANCEL, 0);
    }
    if (s_next.transport == t) s_next.active = false;
}

void loop() {
    if (s_pending && millis() - s_prompt.startedMs > FIDO_USER_TIMEOUT_MS) {
        logEvent("Request timed out");
        finishPending(CTAP2_ERR_USER_ACTION_TIMEOUT, 0);
    }
}

void init() {
    s_pending = false;
    s_next.active = false;
    s_prompt.kind = PromptKind::None;
}

bool submit(CtapTransport t, const uint8_t* msg, size_t len, CtapReplyFn reply) {
    if (len < 1) { replyStatus(reply, CTAP1_ERR_INVALID_LENGTH); return true; }
    if (s_pending) {
        // A second request from the same transport supersedes nothing: the
        // client must wait or cancel. Other transports are told to retry.
        return false;
    }
    uint8_t cmd = msg[0];
    const uint8_t* params = msg + 1;
    size_t plen = len - 1;
    logf("CTAP", "cmd 0x%02X (%u bytes) via %s", cmd, (unsigned)len,
         t == CtapTransport::Ble ? "BLE" : t == CtapTransport::Hybrid ? "hybrid" : "serial");

    if (cmd != CMD_GET_NEXT_ASSERTION) s_next.active = false;

    switch (cmd) {
        case CMD_GET_INFO:
            handleGetInfo(reply);
            return true;
        case CMD_GET_NEXT_ASSERTION:
            handleGetNextAssertion(t, reply);
            return true;
        case CMD_CLIENT_PIN:
            replyStatus(reply, CTAP1_ERR_INVALID_COMMAND);
            return true;
        case CMD_MAKE_CREDENTIAL:
        case CMD_GET_ASSERTION:
        case CMD_RESET:
        case CMD_SELECTION:
            break;
        default:
            replyStatus(reply, CTAP1_ERR_INVALID_COMMAND);
            return true;
    }

    memset(&s_req, 0, sizeof(s_req));
    s_req.cmd = cmd;
    s_transport = t;
    s_reply = reply;
    s_uvDone = false;

    if (cmd == CMD_RESET || cmd == CMD_SELECTION) {
        strlcpy(s_req.rpId, cmd == CMD_RESET ? "ALL PASSKEYS" : "", sizeof(s_req.rpId));
        startPrompt(cmd == CMD_RESET ? PromptKind::Reset : PromptKind::Select);
        return true;
    }

    uint8_t st = cmd == CMD_MAKE_CREDENTIAL ? parseMakeCredential(params, plen, s_req)
                                            : parseGetAssertion(params, plen, s_req);
    if (st == CTAP2_OK && s_req.uv && settings::pinIsSet() && settings::uvSessionActive()) {
        // The PIN was entered on the device earlier in this unlocked session
        // (like an unlocked phone), so this request is user-verified.
        logf("CTAP", "device unlocked: user verification satisfied by the PIN session");
        s_uvDone = true;
    }
    if (st == CTAP2_OK && s_req.uv && !s_req.selectOnly) {
        st = checkUvAvailable();
        if (st == CTAP2_ERR_UNSUPPORTED_OPTION && t == CtapTransport::Hybrid) {
            // Hybrid clients (Windows, Chrome) always request UV because
            // phones always have it. Without a device PIN, fall back to user
            // presence and report UV=0 truthfully; the site decides whether
            // that is acceptable (fine for userVerification "preferred").
            logf("CTAP", "UV requested but no device PIN set: continuing with presence only");
            s_req.uv = false;
            st = CTAP2_OK;
        }
    }
    if (st != CTAP2_OK) {
        logf("CTAP", "request rejected: 0x%02X", st);
        replyStatus(reply, st);
        return true;
    }

    if (s_req.selectOnly) {
        startPrompt(PromptKind::Select);
        return true;
    }

    if (cmd == CMD_GET_ASSERTION) {
        if (!s_req.haveAllowed && s_req.slotCount == 0) {
            logf("CTAP", "no credentials for %s", s_req.rpId);
            replyStatus(reply, CTAP2_ERR_NO_CREDENTIALS);
            return true;
        }
        if (!s_req.up && !s_req.uv) {
            // Silent probe (up=false): sign without user interaction.
            uint8_t status;
            size_t n = completeGetAssertion(&status);
            if (status != CTAP2_OK) replyStatus(reply, status);
            else reply(s_out, n);
            return true;
        }
        startPrompt(PromptKind::Login);
        if ((!s_req.uv || s_uvDone) && settings::autoApprove()) {
            logf("CTAP", "auto-approved sign-in to %s", s_req.rpId);
            complete();
        }
        return true;
    }

    startPrompt(PromptKind::Register);
    if ((!s_req.uv || s_uvDone) && settings::autoApprove()) {
        logf("CTAP", "auto-approved registration for %s", s_req.rpId);
        complete();
    }
    return true;
}

}  // namespace ctap
