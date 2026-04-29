// =============================================================================
// fido2/ble_transport.h — NimBLE FIDO2 GATT Service
// =============================================================================
#pragma once

#include <Arduino.h>

// Callback signature for incoming CTAP2 commands.
// The BLE transport calls this when a full CTAP2 message is received.
// data: raw CTAP2 command bytes
// len: length of the command
typedef void (*CtapCommandCallback)(const uint8_t* data, size_t len);

// Initialize the NimBLE stack and FIDO2 GATT service.
// cmdCallback: function to call when a CTAP2 command arrives.
void bleTransportInit(CtapCommandCallback cmdCallback);

// Send a CTAP2 response back to the connected client via FIDO Status notification.
// data: response bytes
// len: response length
void bleTransportSendResponse(const uint8_t* data, size_t len);

// Check if a BLE client is currently connected.
bool bleTransportIsConnected();

void bleTransportStartAdvertising();

// Generate and start advertising the caBLE v2 EID using the provided QR Secret
void bleTransportStartAdvertisingEID(const uint8_t* qrSecret, const uint8_t* routingId, uint8_t* outPlaintextEid = nullptr);
