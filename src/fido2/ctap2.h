// =============================================================================
// fido2/ctap2.h — CTAP2 Command Handler (Core FIDO2 Logic)
// =============================================================================
#pragma once

#include <Arduino.h>
#include "../config.h"

// CTAP2 Command IDs
#define CTAP2_CMD_MAKE_CREDENTIAL   0x01
#define CTAP2_CMD_GET_ASSERTION     0x02
#define CTAP2_CMD_GET_INFO          0x04
#define CTAP2_CMD_CLIENT_PIN        0x06
#define CTAP2_CMD_RESET             0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x08

// CTAP2 Status Codes
#define CTAP2_OK                    0x00
#define CTAP2_ERR_CBOR_UNEXPECTED   0x11
#define CTAP2_ERR_INVALID_CBOR      0x12
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_INVALID_CREDENTIAL 0x22
#define CTAP2_ERR_NOT_ALLOWED       0x30
#define CTAP2_ERR_OPERATION_DENIED  0x27
#define CTAP2_ERR_KEY_STORE_FULL    0x29
#define CTAP2_ERR_NO_CREDENTIALS    0x2E
#define CTAP2_ERR_KEEPALIVE_CANCEL  0x2D

// Pending FIDO request info (for the UI to display)
struct FidoPendingRequest {
    FidoRequestType type;
    char rpId[FIDO2_RP_ID_MAX_LEN];
    char userName[FIDO2_USER_NAME_MAX_LEN];
    uint8_t clientDataHash[32];
    uint8_t userId[FIDO2_USER_ID_MAX_LEN];
    size_t userIdLen;
    unsigned long timestampMs;       // When the request was received
    bool approved;                   // Set by main loop when user presses APPROVE
    bool processed;                  // Set when the response has been sent
};

// Initialize the CTAP2 handler. Call after cryptoInit() and credStoreInit().
void ctap2Init();

// Process an incoming CTAP2 command (called from BLE transport callback).
// This parses the command, and for MakeCredential/GetAssertion, sets up
// the pending request for the main loop to approve.
void ctap2ProcessCommand(const uint8_t* data, size_t len);

// Get the current pending request (for UI display). Returns nullptr if none.
FidoPendingRequest* ctap2GetPendingRequest();

// Called by the main loop when the user approves a pending request.
void ctap2ApproveRequest();

// Called by the main loop when a pending request times out.
void ctap2DenyRequest();
