// =============================================================================
// fido/ctap2.h — transport-independent CTAP 2.0 authenticator
//
// Transports (BLE, hybrid tunnel, serial) hand complete CTAP messages
// (command byte + CBOR) to ctap::submit() from the main loop. Commands that
// need the user (register / sign-in / reset) raise a prompt for the UI and
// reply once the user approves, denies or the request times out.
// =============================================================================
#pragma once

#include <Arduino.h>
#include "config.h"

enum class CtapTransport : uint8_t { Ble, Hybrid, Serial };

// Called with status byte + CBOR payload.
typedef void (*CtapReplyFn)(const uint8_t* data, size_t len);

enum class PromptKind : uint8_t { None, Register, Login, Reset, Select };

struct CtapPrompt {
    PromptKind    kind;
    CtapTransport transport;
    char          rpId[64];
    char          userName[40];
    bool          needPin;        // built-in user verification requested
    bool          excluded;       // register: already registered on this device
    int           accountCount;   // login: matching discoverable accounts
    uint32_t      startedMs;
};

// CTAP status codes
#define CTAP2_OK                         0x00
#define CTAP1_ERR_INVALID_COMMAND        0x01
#define CTAP1_ERR_INVALID_PARAMETER      0x02
#define CTAP1_ERR_INVALID_LENGTH         0x03
#define CTAP1_ERR_INVALID_SEQ            0x04
#define CTAP1_ERR_TIMEOUT                0x05
#define CTAP1_ERR_CHANNEL_BUSY           0x06
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE   0x11
#define CTAP2_ERR_INVALID_CBOR           0x12
#define CTAP2_ERR_MISSING_PARAMETER      0x14
#define CTAP2_ERR_LIMIT_EXCEEDED         0x15
#define CTAP2_ERR_CREDENTIAL_EXCLUDED    0x19
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM  0x26
#define CTAP2_ERR_OPERATION_DENIED       0x27
#define CTAP2_ERR_KEY_STORE_FULL         0x28
#define CTAP2_ERR_NOT_BUSY               0x29
#define CTAP2_ERR_NO_OPERATION_PENDING   0x2A
#define CTAP2_ERR_UNSUPPORTED_OPTION     0x2B
#define CTAP2_ERR_INVALID_OPTION         0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL       0x2D
#define CTAP2_ERR_NO_CREDENTIALS         0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT    0x2F
#define CTAP2_ERR_NOT_ALLOWED            0x30
#define CTAP2_ERR_PIN_INVALID            0x31
#define CTAP2_ERR_PIN_BLOCKED            0x32
#define CTAP2_ERR_PIN_AUTH_INVALID       0x33
#define CTAP2_ERR_PIN_NOT_SET            0x35
#define CTAP2_ERR_REQUEST_TOO_LARGE      0x39
#define CTAP1_ERR_OTHER                  0x7F

namespace ctap {

void init();

// Submit a CTAP request. The reply may be sent synchronously or later.
// Returns false (and does not call `reply`) if another request is pending.
bool submit(CtapTransport t, const uint8_t* msg, size_t len, CtapReplyFn reply);

void loop();                         // timeouts and deferred work
bool busy();                         // a request is waiting for the user
CtapTransport busyTransport();
void cancel(CtapTransport t);        // client cancelled / disconnected

// UI hooks
const CtapPrompt* prompt();          // nullptr if nothing is pending
void userApprove();
void userDeny();
// For prompts with needPin. Returns true if correct (request then completes).
bool userSubmitPin(const char* pin);

// Encoded authenticatorGetInfo map (without the status byte).
size_t buildGetInfo(uint8_t* out, size_t cap);

}  // namespace ctap
