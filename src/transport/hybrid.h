// =============================================================================
// transport/hybrid.h — FIDO hybrid transport (caBLE v2) authenticator role
//
// The desktop shows a "FIDO:/…" QR code. tools/qr_bridge.py (or the
// serial console) hands that text to the device, which then plays the role
// a phone normally plays:
//   1. connect to wss://cable.ua5v.com/cable/new/<tunnel-id>
//   2. advertise an encrypted EID over BLE so the desktop knows we're near
//   3. run the Noise KNpsk0 handshake through the tunnel
//   4. serve CTAP requests over the encrypted channel
// Protocol details follow Chromium device/fido/cable/v2_handshake.cc.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace hybrid {

enum class State : uint8_t {
    Idle,
    Connecting,      // WiFi / TLS / WebSocket
    Advertising,     // waiting for the desktop's handshake
    Ready,           // encrypted channel up, serving CTAP
    Failed,
};

// Begin a session from QR text ("FIDO:/1234..."). Returns false if the QR
// is invalid. Network work happens in loop().
bool start(const char* qrText);
void stop(const char* reason);
void loop();

State       state();
const char* stateText();       // short human-readable status
const char* requestType();     // "Register" / "Sign in" (from the QR), or ""

}  // namespace hybrid
