// =============================================================================
// fido2/ble_transport.cpp — NimBLE FIDO2 GATT Service
// =============================================================================

#include "ble_transport.h"
#include "cable_tunnel.h"
#include "../config.h"

#include <NimBLEDevice.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>

// =============================================================================
// FIDO2 BLE GATT UUIDs (per FIDO Alliance Spec)
// =============================================================================

// FIDO GATT Service UUID — used for the GATT service that Chrome connects to
// AFTER discovering the EID. Chrome writes Noise handshake data here.
static NimBLEUUID FIDO_SERVICE_UUID((uint16_t)0xFFFD);

// FIDO caBLE Advertisement UUID — this is what Chrome's v2_discovery.cc
// actually scans for in BLE advertisements to find caBLE EIDs.
// caBLE v2 Advertisement Service UUID (0xFFF9 for FIDO)
static NimBLEUUID CABLE_ADV_UUID((uint16_t)0xFFF9);

// FIDO Characteristics (128-bit)
static NimBLEUUID FIDO_CONTROL_POINT_UUID("F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623B3");
static NimBLEUUID FIDO_STATUS_UUID("F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623B3");
static NimBLEUUID FIDO_CONTROL_POINT_LEN_UUID("F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623B3");

// Private Provisioning Service — our custom service for phone→ESP32 key transfer
// This avoids Android's FIDO interception while still using the same callback logic.
static NimBLEUUID PROV_SERVICE_UUID("A3C87500-8ED3-4BDF-8A39-A01BEBEDE295");
static NimBLEUUID PROV_WRITE_UUID("A3C87501-8ED3-4BDF-8A39-A01BEBEDE295");

// =============================================================================
// INTERNAL STATE
// =============================================================================

static NimBLEServer*         s_server = nullptr;
static NimBLECharacteristic* s_controlPoint = nullptr;
static NimBLECharacteristic* s_statusChar = nullptr;
static NimBLECharacteristic* s_controlPointLen = nullptr;
static NimBLEAdvertising*    s_advertising = nullptr;

static CtapCommandCallback   s_cmdCallback = nullptr;
static bool                  s_clientConnected = false;
static bool                  s_eidMode = false;  // true when broadcasting EID
static uint8_t               s_savedQrSecret[16] = {0};
static uint8_t               s_savedRoutingId[3] = {0}; // saved for re-advert on disconnect

// Message reassembly buffer (BLE MTU is small, CTAP2 messages can be large)
static uint8_t  s_rxBuffer[512];
static size_t   s_rxLen = 0;

// =============================================================================
// BLE FRAMING — FIDO over BLE protocol
// =============================================================================
// Per the FIDO BLE spec, messages are framed as:
//   INIT frame:  CMD(1) | HLEN(1) | LLEN(1) | DATA(...)
//   CONT frame:  SEQ(1) | DATA(...)
// CMD byte has bit 7 set for init frames.

#define FIDO_BLE_CMD_MSG    0x83   // CTAP2 CBOR message
#define FIDO_BLE_CMD_CANCEL 0xBE   // Cancel
#define FIDO_BLE_CMD_KEEPALIVE 0x82
#define FIDO_BLE_CMD_ERROR  0xBF

// =============================================================================
// CALLBACKS
// =============================================================================

class FidoServerCallbacks : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override {
        s_clientConnected = true;
        Serial.printf("[BLE] Client connected: %s\n", connInfo.getAddress().toString().c_str());
    }

    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override {
        s_clientConnected = false;
        s_rxLen = 0;  // Reset reassembly buffer
        Serial.printf("[BLE] Client disconnected (reason: %d)\n", reason);
        // If we're in EID mode, restart the EID advertisement (don't overwrite it)
        if (s_eidMode) {
            Serial.println("[BLE] Re-advertising EID after disconnect...");
            bleTransportStartAdvertisingEID(s_savedQrSecret, s_savedRoutingId);
        } else {
            bleTransportStartAdvertising();
        }
    }
};

class ControlPointCallbacks : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pCharacteristic, NimBLEConnInfo& connInfo) override {
        NimBLEAttValue val = pCharacteristic->getValue();
        const uint8_t* data = val.data();
        size_t len = val.size();

        if (len < 1) return;
        
        Serial.printf("[BLE-DEBUG] rx (%d bytes): ", len);
        for(size_t i=0; i<len; i++) Serial.printf("%02X ", data[i]);
        Serial.println();

        uint8_t cmdByte = data[0];

        if (cmdByte & 0x80) {
            // INIT frame — new message
            if (len < 3) {
                Serial.println("[BLE-DEBUG] INIT frame too short!");
                return;
            }

            uint16_t totalLen = ((uint16_t)data[1] << 8) | data[2];

            // Reset reassembly buffer
            s_rxLen = 0;

            // Copy payload (skip 3-byte header)
            size_t payloadLen = len - 3;
            if (payloadLen > 0 && s_rxLen + payloadLen <= sizeof(s_rxBuffer)) {
                memcpy(s_rxBuffer + s_rxLen, data + 3, payloadLen);
                s_rxLen += payloadLen;
            }

            Serial.printf("[BLE-DEBUG] INIT Frame. cmdByte=%02X, totalLen=%d, payloadLen=%d, rxLen=%d\n", cmdByte, totalLen, payloadLen, s_rxLen);

            // Check if message is complete
            if (s_rxLen >= totalLen) {
                // Check for custom caBLE provisioning command
                if (cmdByte == FIDO_BLE_CMD_ERROR && totalLen == 49) {
                    Serial.println("[BLE] Received caBLE Provisioning Payload!");
                    uint8_t hostPubKey[33];
                    uint8_t qrSecret[16];
                    memcpy(hostPubKey, s_rxBuffer, 33);
                    memcpy(qrSecret, s_rxBuffer + 33, 16);
                    // Start the full tunnel flow (WiFi + WebSocket + EID advert)
                    cableTunnelStart(qrSecret, hostPubKey);
                } else {
                    Serial.printf("[BLE] Complete CTAP2 message received (%d bytes)\n", s_rxLen);
                    if (s_cmdCallback) {
                        s_cmdCallback(s_rxBuffer, s_rxLen);
                    }
                }
                s_rxLen = 0;
            }
        } else {
            // CONTINUATION frame
            size_t payloadLen = len - 1;  // Skip 1-byte sequence number
            if (payloadLen > 0 && s_rxLen + payloadLen <= sizeof(s_rxBuffer)) {
                memcpy(s_rxBuffer + s_rxLen, data + 1, payloadLen);
                s_rxLen += payloadLen;
            }
            // Note: In a full implementation, we'd track totalLen from the INIT
            // frame and check completion here. For now, we rely on the CTAP2
            // layer to detect complete messages.
        }
    }
};

// Static callback instances
static FidoServerCallbacks   s_serverCallbacks;
static ControlPointCallbacks s_cpCallbacks;

// =============================================================================
// PUBLIC API
// =============================================================================

void bleTransportInit(CtapCommandCallback cmdCallback) {
    s_cmdCallback = cmdCallback;

    Serial.println("[BLE] Initializing NimBLE FIDO2 stack...");

    // Initialize NimBLE
    NimBLEDevice::init(BLE_DEVICE_NAME);



    // Print our own MAC address so it's easy to spot in Chrome logs
    Serial.printf("[BLE] Device MAC Address: %s\n", NimBLEDevice::getAddress().toString().c_str());

    NimBLEDevice::setPower(ESP_PWR_LVL_P9);           // Max TX power

    // Create BLE Server
    s_server = NimBLEDevice::createServer();
    s_server->setCallbacks(&s_serverCallbacks);

    // Create FIDO Service (kept for future Chrome EID handshake, NOT for provisioning)
    NimBLEService* fidoService = s_server->createService(FIDO_SERVICE_UUID);

    // FIDO Control Point — for future CTAP2 from Chrome desktop
    s_controlPoint = fidoService->createCharacteristic(
        FIDO_CONTROL_POINT_UUID,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    s_controlPoint->setCallbacks(&s_cpCallbacks);

    // FIDO Status — Authenticator sends responses via notification
    s_statusChar = fidoService->createCharacteristic(
        FIDO_STATUS_UUID,
        NIMBLE_PROPERTY::NOTIFY
    );

    // FIDO Control Point Length — Reports max write size
    s_controlPointLen = fidoService->createCharacteristic(
        FIDO_CONTROL_POINT_LEN_UUID,
        NIMBLE_PROPERTY::READ
    );
    // Set control point length to our buffer size (2 bytes, big-endian)
    uint8_t cpLen[2] = { (uint8_t)(sizeof(s_rxBuffer) >> 8), (uint8_t)(sizeof(s_rxBuffer) & 0xFF) };
    s_controlPointLen->setValue(cpLen, 2);

    // =================================================================
    // Private Provisioning Service — phone app writes keys here.
    // Uses a custom UUID so Android's built-in FIDO subsystem won't
    // intercept the GATT operations (which blocks writes to 0xFFFD).
    // =================================================================
    NimBLEService* provService = s_server->createService(PROV_SERVICE_UUID);
    auto* provChar = provService->createCharacteristic(
        PROV_WRITE_UUID,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    provChar->setCallbacks(&s_cpCallbacks); // Same callback as FIDO CP

    // --- Device Information Service ---
    NimBLEService* disService = s_server->createService("180A");
    disService->createCharacteristic("2A29", NIMBLE_PROPERTY::READ)
              ->setValue("AuthKey");
    disService->createCharacteristic("2A24", NIMBLE_PROPERTY::READ)
              ->setValue("ESP32-Auth-v1");
    disService->createCharacteristic("2A26", NIMBLE_PROPERTY::READ)
              ->setValue("1.0.0");

    Serial.println("[BLE] FIDO2 + Provisioning GATT services created.");

    // In NimBLE-Arduino 2.x, server->start() registers the full GATT
    // attribute table with the NimBLE host stack (calls ble_gatts_start()).
    // Without this, all characteristic reads/writes silently fail.
    s_server->start();

    // Start advertising
    bleTransportStartAdvertising();
}

void bleTransportSendResponse(const uint8_t* data, size_t len) {
    if (!s_clientConnected || !s_statusChar) {
        Serial.println("[BLE] Cannot send — no client connected.");
        return;
    }

    // Frame as FIDO BLE INIT response
    // Header: CMD(1) | HLEN(1) | LLEN(1) | DATA
    size_t mtu = NimBLEDevice::getMTU() - 3;  // Usable payload per packet
    if (mtu < 20) mtu = 20;

    // Build INIT frame
    uint8_t frame[512];
    size_t frameLen = 0;

    frame[0] = FIDO_BLE_CMD_MSG;               // CMD byte
    frame[1] = (uint8_t)((len >> 8) & 0xFF);   // Total length high
    frame[2] = (uint8_t)(len & 0xFF);           // Total length low
    frameLen = 3;

    size_t dataOffset = 0;
    size_t firstChunkLen = (mtu - 3 < len) ? (mtu - 3) : len;
    memcpy(frame + 3, data, firstChunkLen);
    frameLen += firstChunkLen;
    dataOffset += firstChunkLen;

    s_statusChar->setValue(frame, frameLen);
    s_statusChar->notify();
    delay(20);  // Give BLE stack time

    // Send continuation frames if needed
    uint8_t seq = 0;
    while (dataOffset < len) {
        frameLen = 0;
        frame[0] = seq++;  // Sequence number (bit 7 = 0 for CONT)
        frameLen = 1;

        size_t chunkLen = ((len - dataOffset) < (mtu - 1)) ? (len - dataOffset) : (mtu - 1);
        memcpy(frame + 1, data + dataOffset, chunkLen);
        frameLen += chunkLen;
        dataOffset += chunkLen;

        s_statusChar->setValue(frame, frameLen);
        s_statusChar->notify();
        delay(20);
    }

    Serial.printf("[BLE] Sent response (%d bytes)\n", len);
}

bool bleTransportIsConnected() {
    return s_clientConnected;
}

void bleTransportStartAdvertising() {
    s_advertising = NimBLEDevice::getAdvertising();
    s_advertising->addServiceUUID(PROV_SERVICE_UUID); // Advertise provisioning service
    s_advertising->setName(BLE_DEVICE_NAME);
    s_advertising->start();
    Serial.println("[BLE] Advertising as: " BLE_DEVICE_NAME);
}

void custom_hkdf_sha256(const uint8_t* ikm, size_t ikm_len, 
                        const uint8_t* info, size_t info_len, 
                        uint8_t* okm, size_t okm_len) {
    // HKDF-Extract: PRK = HMAC-SHA256(salt="", IKM)
    uint8_t prk[32];
    uint8_t salt[32] = {0}; // If salt is not provided, it is set to a string of HashLen zeros.
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, ikm, ikm_len, prk);
    
    // HKDF-Expand
    uint8_t t[32];
    size_t out_offset = 0;
    uint8_t counter = 1;
    
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    
    while (out_offset < okm_len) {
        mbedtls_md_hmac_starts(&ctx, prk, 32);
        if (counter > 1) {
            mbedtls_md_hmac_update(&ctx, t, 32);
        }
        mbedtls_md_hmac_update(&ctx, info, info_len);
        mbedtls_md_hmac_update(&ctx, &counter, 1);
        mbedtls_md_hmac_finish(&ctx, t);
        
        size_t to_copy = (okm_len - out_offset) > 32 ? 32 : (okm_len - out_offset);
        memcpy(okm + out_offset, t, to_copy);
        out_offset += to_copy;
        counter++;
    }
    mbedtls_md_free(&ctx);
}

void bleTransportStartAdvertisingEID(const uint8_t* qrSecret, const uint8_t* routingId, uint8_t* outPlaintextEid) {
    Serial.println("[BLE] Generating caBLE v2 EID...");
    
    // Save QR secret and routing ID so we can re-advertise after phone disconnect
    memcpy(s_savedQrSecret, qrSecret, 16);
    if (routingId) {
        memcpy(s_savedRoutingId, routingId, 3);
    }
    s_eidMode = true;
    
    // 1. Derive EIDKey (64 bytes) from QR Secret (16 bytes)
    uint8_t eidKey[64];
    uint32_t type = 1; // DerivedValueType::kEIDKey
    
    custom_hkdf_sha256(qrSecret, 16, (const uint8_t*)&type, 4, eidKey, 64);
    
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    
    // 2. Construct Plaintext EID (16 bytes)
    uint8_t plaintext[16] = {0};
    plaintext[0] = 0; // version 0
    // Random 8-byte nonce
    for (int i = 0; i < 8; i++) plaintext[1+i] = random(256);
    // 3-byte routing ID
    memcpy(plaintext + 9, s_savedRoutingId, 3);
    // 2-byte tunnel server domain (Google's cable.ua5v.com is 0)
    plaintext[12] = 0x00;
    plaintext[13] = 0x00;
    // 14..15 are 0 padding

    if (outPlaintextEid) {
        memcpy(outPlaintextEid, plaintext, 16);
    }

    
    // 3. Encrypt Plaintext using AES-256-ECB
    uint8_t ciphertext[16];
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, eidKey, 256);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
    mbedtls_aes_free(&aes);
    
    // 4. Compute HMAC-SHA256 over ciphertext
    uint8_t hmac[32];
    mbedtls_md_hmac_starts(&ctx, eidKey + 32, 32);
    mbedtls_md_hmac_update(&ctx, ciphertext, 16);
    mbedtls_md_hmac_finish(&ctx, hmac);
    mbedtls_md_free(&ctx);
    
    // 5. Construct final 20-byte EID
    uint8_t finalEid[20];
    memcpy(finalEid, ciphertext, 16);
    memcpy(finalEid + 16, hmac, 4);
    
    Serial.printf("[BLE] EID (20 bytes): ");
    for (int i = 0; i < 20; i++) Serial.printf("%02X ", finalEid[i]);
    Serial.println();
    
    // 6. Update NimBLE Advertisement — must be connectable for Chrome to connect
    s_advertising = NimBLEDevice::getAdvertising();
    s_advertising->stop();
    s_advertising->clearData();
    
    NimBLEAdvertisementData advData;
    advData.setFlags(BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP);
    
    // FIDO caBLE v2 Service UUID: 0xFFF9
    NimBLEUUID fidoCableUuid("FFF9");
    // advData.setCompleteServices(fidoCableUuid); // Required for OS-level scanners to forward it to Chrome
    // Removed setCompleteServices to save 4 bytes so it fits perfectly in the 31-byte primary packet.
    
    // Service Data: UUID(0xFFF9) + exactly 20 bytes EID
    // Chrome checks: service_data->size() == kAdvertSize (20)
    std::string serviceData;
    serviceData.append((char*)finalEid, 20);
    
    advData.setServiceData(CABLE_ADV_UUID, serviceData);
    
    s_advertising->setAdvertisementData(advData);
    s_advertising->start();
    Serial.println("[BLE] EID Advertisement Started! Desktop should connect now.");
}
