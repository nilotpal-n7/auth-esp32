#include "transport/ble.h"
#include "config.h"
#include "core/log.h"
#include "fido/ctap2.h"
#include "unlock/unlock.h"

#include <NimBLEDevice.h>
#include <freertos/FreeRTOS.h>

namespace ble {

// FIDO Alliance assigned UUIDs (note the ...623BB suffix).
static const NimBLEUUID FIDO_SERVICE_UUID((uint16_t)0xFFFD);
static const NimBLEUUID FIDO_CONTROL_POINT_UUID("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB");
static const NimBLEUUID FIDO_STATUS_UUID("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB");
static const NimBLEUUID FIDO_CP_LENGTH_UUID("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB");
static const NimBLEUUID FIDO_REVISION_BITS_UUID("F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB");
static const NimBLEUUID FIDO_REVISION_UUID((uint16_t)0x2A28);
static const NimBLEUUID CABLE_UUID((uint16_t)0xFFF9);

static const NimBLEUUID PROV_SERVICE_UUID("A3C87500-8ED3-4BDF-8A39-A01BEBEDE295");
static const NimBLEUUID PROV_WRITE_UUID("A3C87501-8ED3-4BDF-8A39-A01BEBEDE295");
static const NimBLEUUID PROV_STATUS_UUID("A3C87502-8ED3-4BDF-8A39-A01BEBEDE295");
// PC unlock: write pcId(8) || challenge(32); notified: status(1, 0 = ok) || mac(32)
static const NimBLEUUID UNLOCK_UUID("A3C87503-8ED3-4BDF-8A39-A01BEBEDE295");

// BLE framing commands (CTAP 2.0 §8.3.4)
#define BLE_CMD_PING       0x81
#define BLE_CMD_KEEPALIVE  0x82
#define BLE_CMD_MSG        0x83
#define BLE_CMD_CANCEL     0xBE
#define BLE_CMD_ERROR      0xBF
#define BLE_ERR_INVALID_CMD 0x01
#define BLE_ERR_INVALID_LEN 0x03
#define BLE_ERR_INVALID_SEQ 0x04
#define BLE_ERR_BUSY        0x06
#define KEEPALIVE_UP_NEEDED 0x02
#define REVISION_FIDO2      0x20

static NimBLEServer*         s_server = nullptr;
static NimBLECharacteristic* s_status = nullptr;
static NimBLECharacteristic* s_cpLength = nullptr;
static NimBLECharacteristic* s_provStatus = nullptr;

static volatile bool s_connected = false;
static volatile bool s_secured = false;
static volatile uint16_t s_connHandle = BLE_HS_CONN_HANDLE_NONE;
static volatile uint16_t s_mtu = 23;

// Pairing confirmation, raised in the NimBLE task and answered from the UI.
static volatile bool s_pairPending = false;
static uint32_t      s_pairCode = 0;
static NimBLEConnInfo* s_pairConn = nullptr;
static uint8_t       s_pairConnStorage[sizeof(NimBLEConnInfo)] __attribute__((aligned(4)));

// Hybrid advertising
static bool    s_hybridAdvert = false;
static uint8_t s_eid[20];

// --- RX reassembly (NimBLE task) → completed message (main loop) ------------

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static uint8_t  s_rx[FIDO_MAX_MSG];
static size_t   s_rxLen = 0, s_rxExpected = 0;
static uint8_t  s_rxCmd = 0;
static int      s_rxSeq = -1;
static bool     s_rxActive = false;

static uint8_t  s_msg[FIDO_MAX_MSG];      // completed message waiting for loop()
static size_t   s_msgLen = 0;
static uint8_t  s_msgCmd = 0;
static volatile bool s_msgReady = false;
static volatile bool s_cancelRequested = false;
static volatile uint8_t s_errorToSend = 0;

static char     s_prov[512];
static volatile bool s_provReady = false;

static uint32_t s_lastKeepalive = 0;

// --- TX ---------------------------------------------------------------------

static void notifyFragment(const uint8_t* data, size_t len) {
    for (int attempt = 0; attempt < 50 && s_connected; attempt++) {
        if (s_status->notify(data, len, s_connHandle)) return;
        delay(5);   // out of mbufs: wait for the controller to drain
    }
}

static void sendFrame(uint8_t cmd, const uint8_t* data, size_t len) {
    if (!s_connected || !s_status) return;
    size_t frag = s_mtu > 3 ? s_mtu - 3 : 20;
    if (frag > 512) frag = 512;
    uint8_t buf[512];

    size_t first = len < frag - 3 ? len : frag - 3;
    buf[0] = cmd;
    buf[1] = (uint8_t)(len >> 8);
    buf[2] = (uint8_t)len;
    memcpy(buf + 3, data, first);
    notifyFragment(buf, first + 3);

    size_t off = first;
    uint8_t seq = 0;
    while (off < len && s_connected) {
        size_t n = len - off < frag - 1 ? len - off : frag - 1;
        buf[0] = seq++ & 0x7F;
        memcpy(buf + 1, data + off, n);
        notifyFragment(buf, n + 1);
        off += n;
    }
}

static void sendError(uint8_t code) { sendFrame(BLE_CMD_ERROR, &code, 1); }

static void ctapReply(const uint8_t* data, size_t len) {
    sendFrame(BLE_CMD_MSG, data, len);
}

// --- Advertising -------------------------------------------------------------

static void applyAdvertising() {
    NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
    adv->stop();
    NimBLEAdvertisementData data, scan;
    data.setFlags(BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP);
    if (s_hybridAdvert) {
        // caBLE v2: 20-byte encrypted EID as service data for UUID 0xFFF9.
        data.setServiceData(CABLE_UUID, s_eid, sizeof(s_eid));
        adv->setConnectableMode(BLE_GAP_CONN_MODE_NON);
    } else {
        data.setCompleteServices16({FIDO_SERVICE_UUID});
        // FIDO service data: 0x80 = pairing mode (we accept pairing at any
        // time, gated by on-device numeric comparison).
        uint8_t fidoSvcData = 0x80;
        data.setServiceData(FIDO_SERVICE_UUID, &fidoSvcData, 1);
        adv->setConnectableMode(BLE_GAP_CONN_MODE_UND);
    }
    scan.setName(FW_NAME);
    scan.addServiceUUID(PROV_SERVICE_UUID);
    adv->setAdvertisementData(data);
    adv->setScanResponseData(scan);
    adv->enableScanResponse(true);
    if (!s_connected) adv->start();
}

void startHybridAdvert(const uint8_t eid[20]) {
    memcpy(s_eid, eid, 20);
    s_hybridAdvert = true;
    // Only one BLE link is supported and advertising stops while connected,
    // so a lingering client (e.g. a PC that left a GATT session open) would
    // hide the EID from the desktop. Drop it unless it is mid-CTAP request;
    // onDisconnect() then starts the EID advert.
    if (s_connected && !(ctap::busy() && ctap::busyTransport() == CtapTransport::Ble)) {
        logf("BLE", "dropping idle client so the hybrid advert can run");
        s_server->disconnect(s_connHandle);
        return;
    }
    applyAdvertising();
}

void stopHybridAdvert() {
    if (!s_hybridAdvert) return;
    s_hybridAdvert = false;
    applyAdvertising();
}

// --- Callbacks (NimBLE host task) -------------------------------------------

class ServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer*, NimBLEConnInfo& info) override {
        s_connected = true;
        s_secured = info.isEncrypted();
        s_connHandle = info.getConnHandle();
        s_mtu = info.getMTU();
        portENTER_CRITICAL(&s_mux);
        s_rxActive = false;
        portEXIT_CRITICAL(&s_mux);
        logf("BLE", "connected: %s", info.getAddress().toString().c_str());
    }

    void onDisconnect(NimBLEServer*, NimBLEConnInfo& info, int reason) override {
        s_connected = false;
        s_secured = false;
        s_connHandle = BLE_HS_CONN_HANDLE_NONE;
        s_pairPending = false;
        s_cancelRequested = true;       // abort any request from this link
        logf("BLE", "disconnected (reason 0x%02X)", reason);
        applyAdvertising();
    }

    void onMTUChange(uint16_t mtu, NimBLEConnInfo&) override { s_mtu = mtu; }

    void onConfirmPassKey(NimBLEConnInfo& info, uint32_t code) override {
        // Keep a copy; the UI answers later via pairingConfirm().
        s_pairConn = new (s_pairConnStorage) NimBLEConnInfo(info);
        s_pairCode = code;
        s_pairPending = true;
        logf("BLE", "pairing request, code %06lu", (unsigned long)code);
    }

    void onAuthenticationComplete(NimBLEConnInfo& info) override {
        s_pairPending = false;
        s_secured = info.isEncrypted();
        if (!info.isEncrypted()) {
            logf("BLE", "pairing failed");
            NimBLEDevice::getServer()->disconnect(info.getConnHandle());
        } else {
            logEvent("BLE paired/secured");
        }
    }
};

class ControlPointCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& info) override {
        NimBLEAttValue v = c->getValue();
        const uint8_t* d = v.data();
        size_t n = v.size();
        if (n == 0) return;

        portENTER_CRITICAL(&s_mux);
        uint8_t err = 0;
        if (d[0] & 0x80) {
            // Initialisation fragment: CMD | HLEN | LLEN | DATA
            if (n < 3) err = BLE_ERR_INVALID_LEN;
            else {
                s_rxCmd = d[0];
                s_rxExpected = ((size_t)d[1] << 8) | d[2];
                s_rxLen = 0;
                s_rxSeq = -1;
                s_rxActive = true;
                if (s_rxExpected > sizeof(s_rx)) { err = BLE_ERR_INVALID_LEN; s_rxActive = false; }
                else {
                    size_t c0 = n - 3 > s_rxExpected ? s_rxExpected : n - 3;
                    memcpy(s_rx, d + 3, c0);
                    s_rxLen = c0;
                }
            }
        } else if (s_rxActive) {
            // Continuation fragment: SEQ | DATA
            if (d[0] != (uint8_t)((s_rxSeq + 1) & 0x7F)) { err = BLE_ERR_INVALID_SEQ; s_rxActive = false; }
            else {
                s_rxSeq = d[0];
                size_t c = n - 1;
                if (s_rxLen + c > s_rxExpected) c = s_rxExpected - s_rxLen;
                memcpy(s_rx + s_rxLen, d + 1, c);
                s_rxLen += c;
            }
        } else {
            err = BLE_ERR_INVALID_SEQ;
        }

        if (!err && s_rxActive && s_rxLen >= s_rxExpected) {
            s_rxActive = false;
            if (s_rxCmd == BLE_CMD_CANCEL) {
                s_cancelRequested = true;
            } else if (s_msgReady) {
                err = BLE_ERR_BUSY;
            } else {
                memcpy(s_msg, s_rx, s_rxLen);
                s_msgLen = s_rxLen;
                s_msgCmd = s_rxCmd;
                s_msgReady = true;
            }
        }
        if (err) s_errorToSend = err;
        portEXIT_CRITICAL(&s_mux);
    }
};

class CpLengthCallbacks : public NimBLECharacteristicCallbacks {
    void onRead(NimBLECharacteristic* c, NimBLEConnInfo& info) override {
        uint16_t len = info.getMTU() - 3;
        if (len < 20) len = 20;
        if (len > 512) len = 512;
        uint8_t v[2] = {(uint8_t)(len >> 8), (uint8_t)len};
        c->setValue(v, 2);
    }
};

class RevisionBitsCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        // Only FIDO2 is supported; reflect that whatever the client selects.
        uint8_t v = REVISION_FIDO2;
        c->setValue(&v, 1);
    }
};

static NimBLECharacteristic* s_unlockChar = nullptr;
static uint8_t       s_unlockReq[UNLOCK_PC_ID_LEN + UNLOCK_CHAL_LEN];
static volatile bool s_unlockReady = false;

class UnlockCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        NimBLEAttValue v = c->getValue();
        if (v.size() != sizeof(s_unlockReq) || s_unlockReady) return;
        portENTER_CRITICAL(&s_mux);
        memcpy(s_unlockReq, v.data(), sizeof(s_unlockReq));
        s_unlockReady = true;
        portEXIT_CRITICAL(&s_mux);
    }
};

static void bleUnlockReply(bool ok, const uint8_t* mac, void*) {
    uint8_t out[33] = {0};
    out[0] = ok ? 0 : 1;
    if (ok && mac) memcpy(out + 1, mac, 32);
    s_unlockChar->setValue(out, sizeof(out));
    if (s_connected) s_unlockChar->notify();
}

class ProvisionCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* c, NimBLEConnInfo&) override {
        NimBLEAttValue v = c->getValue();
        size_t n = v.size() < sizeof(s_prov) - 1 ? v.size() : sizeof(s_prov) - 1;
        portENTER_CRITICAL(&s_mux);
        memcpy(s_prov, v.data(), n);
        s_prov[n] = '\0';
        s_provReady = true;
        portEXIT_CRITICAL(&s_mux);
    }
};

static ServerCallbacks       s_serverCb;
static ControlPointCallbacks s_cpCb;
static CpLengthCallbacks     s_cpLenCb;
static RevisionBitsCallbacks s_revCb;
static ProvisionCallbacks    s_provCb;
static UnlockCallbacks       s_unlockCb;

// --- Public API --------------------------------------------------------------

void init() {
    NimBLEDevice::init(FW_NAME);
    NimBLEDevice::setPower(9);
    NimBLEDevice::setMTU(512);
    // Bonding + MITM + LE Secure Connections, numeric comparison on the OLED.
    NimBLEDevice::setSecurityAuth(true, true, true);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_YESNO);

    s_server = NimBLEDevice::createServer();
    s_server->setCallbacks(&s_serverCb);
    s_server->advertiseOnDisconnect(false);   // handled in onDisconnect

    NimBLEService* fido = s_server->createService(FIDO_SERVICE_UUID);
    NimBLECharacteristic* cp = fido->createCharacteristic(
        FIDO_CONTROL_POINT_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_ENC);
    cp->setCallbacks(&s_cpCb);
    s_status = fido->createCharacteristic(FIDO_STATUS_UUID, NIMBLE_PROPERTY::NOTIFY);
    s_cpLength = fido->createCharacteristic(
        FIDO_CP_LENGTH_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_ENC);
    s_cpLength->setCallbacks(&s_cpLenCb);
    uint8_t cpl[2] = {0, 20};
    s_cpLength->setValue(cpl, 2);
    NimBLECharacteristic* rev = fido->createCharacteristic(
        FIDO_REVISION_BITS_UUID,
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::READ_ENC |
            NIMBLE_PROPERTY::WRITE_ENC);
    uint8_t revBits = REVISION_FIDO2;
    rev->setValue(&revBits, 1);
    rev->setCallbacks(&s_revCb);
    fido->createCharacteristic(FIDO_REVISION_UUID, NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_ENC)
        ->setValue("2.0");

    NimBLEService* prov = s_server->createService(PROV_SERVICE_UUID);
    prov->createCharacteristic(PROV_WRITE_UUID, NIMBLE_PROPERTY::WRITE)->setCallbacks(&s_provCb);
    s_provStatus = prov->createCharacteristic(PROV_STATUS_UUID,
                                              NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
    s_provStatus->setValue("idle");
    s_unlockChar = prov->createCharacteristic(UNLOCK_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::NOTIFY);
    s_unlockChar->setCallbacks(&s_unlockCb);

    NimBLEService* dis = s_server->createService((uint16_t)0x180A);
    dis->createCharacteristic((uint16_t)0x2A29, NIMBLE_PROPERTY::READ)->setValue("AuthKey");
    dis->createCharacteristic((uint16_t)0x2A24, NIMBLE_PROPERTY::READ)->setValue(FW_NAME);
    dis->createCharacteristic((uint16_t)0x2A26, NIMBLE_PROPERTY::READ)->setValue(FW_VERSION);

    s_server->start();
    applyAdvertising();
    logf("BLE", "ready, address %s, %d bond(s)", NimBLEDevice::getAddress().toString().c_str(),
         NimBLEDevice::getNumBonds());
}

void loop() {
    if (s_errorToSend) {
        uint8_t e = s_errorToSend;
        s_errorToSend = 0;
        sendError(e);
    }

    if (s_cancelRequested) {
        s_cancelRequested = false;
        ctap::cancel(CtapTransport::Ble);
    }

    if (s_unlockReady) {
        uint8_t req[sizeof(s_unlockReq)];
        portENTER_CRITICAL(&s_mux);
        memcpy(req, s_unlockReq, sizeof(req));
        s_unlockReady = false;
        portEXIT_CRITICAL(&s_mux);
        unlock::respond(req, req + UNLOCK_PC_ID_LEN, UNLOCK_CHAL_LEN, "Bluetooth", bleUnlockReply, nullptr);
    }

    if (s_msgReady) {
        static uint8_t msg[FIDO_MAX_MSG];
        size_t len;
        uint8_t cmd;
        portENTER_CRITICAL(&s_mux);
        len = s_msgLen;
        cmd = s_msgCmd;
        memcpy(msg, s_msg, len);
        s_msgReady = false;
        portEXIT_CRITICAL(&s_mux);

        if (!s_secured) {
            // Should not happen (the control point requires encryption).
            sendError(BLE_ERR_INVALID_CMD);
        } else if (cmd == BLE_CMD_PING) {
            sendFrame(BLE_CMD_PING, msg, len);
        } else if (cmd == BLE_CMD_MSG) {
            if (!ctap::submit(CtapTransport::Ble, msg, len, ctapReply)) sendError(BLE_ERR_BUSY);
        } else {
            sendError(BLE_ERR_INVALID_CMD);
        }
    }

    // Keepalive while waiting for the user (CTAP 2.0 §8.3.4.3)
    if (ctap::busy() && ctap::busyTransport() == CtapTransport::Ble && s_connected &&
        millis() - s_lastKeepalive > 400) {
        s_lastKeepalive = millis();
        uint8_t status = KEEPALIVE_UP_NEEDED;
        sendFrame(BLE_CMD_KEEPALIVE, &status, 1);
    }
}

bool connected() { return s_connected; }
bool secured() { return s_secured; }

bool pairingPending(uint32_t* code) {
    if (s_pairPending && code) *code = s_pairCode;
    return s_pairPending;
}

void pairingConfirm(bool accept) {
    if (!s_pairPending || !s_pairConn) return;
    s_pairPending = false;
    NimBLEDevice::injectConfirmPasskey(*s_pairConn, accept);
    logEvent(accept ? "BLE pairing accepted" : "BLE pairing rejected");
}

int  bondCount() { return NimBLEDevice::getNumBonds(); }
void forgetBonds() { NimBLEDevice::deleteAllBonds(); }

bool takeProvisioning(char* out, size_t cap) {
    if (!s_provReady) return false;
    portENTER_CRITICAL(&s_mux);
    strlcpy(out, s_prov, cap);
    s_provReady = false;
    portEXIT_CRITICAL(&s_mux);
    return true;
}

void setHybridStatus(const char* status) {
    if (!s_provStatus) return;
    s_provStatus->setValue(status);
    if (s_connected) s_provStatus->notify();
}

}  // namespace ble
