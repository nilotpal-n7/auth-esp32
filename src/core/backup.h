// =============================================================================
// core/backup.h — encrypted backup / restore of everything that can't be
// recreated: the FIDO master key (every passkey derives from it), discoverable
// passkey records, the signature counter, TOTP accounts and paired PCs.
//
// The PC tool (tools/authkey.py backup|restore) turns a passphrase into a key
// with PBKDF2 and sends only that key; the device encrypts / decrypts with
// AES-256-GCM, so the console never carries the secrets in the clear. Both
// directions must be confirmed on the device (plus the device PIN if set).
//
// Console protocol (hex everywhere):
//   backup <key64>                       -> "BACKUP nonce <24>", "BACKUP data <...>"..., "OK backup <n>"
//   restore begin <key64> <nonce24> <n>  -> "OK"
//   restore data <hex>                   -> "OK" (repeat)
//   restore end                          -> asks on the device, then "OK restored" and a reboot
// =============================================================================
#pragma once

#include <Arduino.h>

namespace backup {

void exportStart(const uint8_t key[32]);
void restoreBegin(const uint8_t key[32], const uint8_t nonce[12], size_t len);
void restoreData(const char* hex);
void restoreEnd();

}  // namespace backup
