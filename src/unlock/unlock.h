// =============================================================================
// unlock/unlock.h — Windows sign-in (PC unlock) challenge-response
//
// Each paired PC shares a random 32-byte key with the device. To unlock, the
// PC's AuthKey service sends a fresh random challenge and the device answers
//
//   HMAC-SHA256(key, "AuthKey unlock v1" || pcId || challenge)
//
// over USB serial, BLE or WiFi (TCP). Pairing always needs the OK button;
// unlocking is automatic when auto-approve is on, otherwise it asks for OK.
// =============================================================================
#pragma once

#include <Arduino.h>

#define UNLOCK_PC_ID_LEN   8
#define UNLOCK_KEY_LEN     32
#define UNLOCK_CHAL_LEN    32
#define UNLOCK_MAX_PCS     4
#define UNLOCK_TCP_PORT    7623

namespace unlock {

// One paired PC (also the record format in backups).
struct PcEntry {
    uint8_t id[UNLOCK_PC_ID_LEN];
    uint8_t key[UNLOCK_KEY_LEN];
    char    name[24];
};

// Called with ok=false (denied / unknown PC / timeout) or the 32-byte answer.
typedef void (*ReplyFn)(bool ok, const uint8_t* mac, void* ctx);

enum class PromptKind : uint8_t { None, Pair, Unlock };

struct Prompt {
    PromptKind kind;
    char       name[24];
    const char* via;
    uint32_t   startedMs;
};

void init();
void loop();                       // WiFi TCP server + prompt timeout

// Start pairing (always asks the user). Reply mac is null; ok = paired.
bool pair(const uint8_t pcId[UNLOCK_PC_ID_LEN], const uint8_t key[UNLOCK_KEY_LEN],
          const char* name, const char* via, ReplyFn reply, void* ctx);
// Answer a challenge (possibly after asking the user).
void respond(const uint8_t pcId[UNLOCK_PC_ID_LEN], const uint8_t* challenge, size_t len,
             const char* via, ReplyFn reply, void* ctx);

int  count();
bool getEntry(int index, PcEntry* out);       // index in [0, UNLOCK_MAX_PCS)
// Replace every paired PC (backup restore).
void replaceAll(const PcEntry* entries, int n);
bool name(int index, char* out, size_t cap);
bool remove(int index);

// UI hooks
const Prompt* prompt();
void userApprove();
void userDeny();

}  // namespace unlock
