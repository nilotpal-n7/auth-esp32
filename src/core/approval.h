// =============================================================================
// core/approval.h — "press OK on the device" confirmations for local features
//
// Backup export, restore and new web-page sessions must be confirmed on the
// device itself, so software on a PC (or another device on the network) can't
// do them alone. When a device PIN is set, backup and restore also need it.
// One request at a time; it times out after FIDO_USER_TIMEOUT_MS.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace approval {

// Called once with the outcome (approved = true) from the main loop.
typedef void (*DoneFn)(bool approved, void* ctx);

struct Request {
    char     title[22];       // e.g. "EXPORT BACKUP?"
    char     detail[40];      // e.g. "3 passkeys, 5 TOTP"
    char     hint[32];        // smaller line, e.g. "from 172.16.114.193"
    bool     needPin;
    uint32_t startedMs;
};

// False if another request is waiting.
bool ask(const char* title, const char* detail, const char* hint, bool needPin, DoneFn done, void* ctx);
const Request* pending();     // nullptr when nothing is waiting

// UI hooks
void approve();               // ignored while a PIN is still required
void deny();
bool submitPin(const char* pin);   // true = correct (request then completes)

void loop();                  // timeout

#ifdef AUTHKEY_TEST_HOOKS
void forceApprove();          // test builds only: approve without the PIN
#endif

}  // namespace approval
