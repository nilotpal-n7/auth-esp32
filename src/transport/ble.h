// =============================================================================
// transport/ble.h — NimBLE peripheral: FIDO BLE transport + hybrid helper
//
// Services:
//   0xFFFD  FIDO (CTAP over BLE, FIDO CTAP 2.0 §8.3). Encrypted + bonded,
//           LE Secure Connections with numeric comparison on the OLED.
//   A3C87500-… AuthKey hybrid provisioning: tools/qr_bridge.py (PC) writes
//           the "FIDO:/…" QR text here; status is notified back.
//   0x180A  Device Information.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace ble {

void init();
void loop();                       // main-loop work: RX dispatch, keepalives

bool connected();
bool secured();                    // encrypted link

// Pairing (numeric comparison) — the UI shows `code` and asks the user.
bool pairingPending(uint32_t* code);
void pairingConfirm(bool accept);
int  bondCount();
void forgetBonds();

// Hybrid: advertise a caBLE v2 EID (20 bytes) instead of the normal advert.
void startHybridAdvert(const uint8_t eid[20]);
void stopHybridAdvert();

// Hybrid QR text written over BLE (tools/qr_bridge.py). True once per QR.
bool takeProvisioning(char* out, size_t cap);
// Short status string notified to the BLE client ("connecting", ...).
void setHybridStatus(const char* status);

}  // namespace ble
