// =============================================================================
// fido2/cable_tunnel.h — caBLE v2 WebSocket Tunnel + Noise Handshake
// =============================================================================
#pragma once

#include <Arduino.h>

// Start the caBLE tunnel: reconnect WiFi, connect to tunnel server,
// and begin advertising the EID. Called when provisioning payload arrives.
//   qrSecret:     16-byte QR secret from the scanned QR code
//   peerIdentity: 33-byte compressed P-256 public key of the browser (from QR)
void cableTunnelStart(const uint8_t* qrSecret, const uint8_t* peerIdentity);

// Process WebSocket events. Call from main loop().
void cableTunnelLoop();

// Check if the tunnel is currently active.
bool cableTunnelIsActive();
