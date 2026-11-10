// =============================================================================
// net/telegram.h — Telegram bot: remote control and notifications
//
// Polls Telegram (long polling: nothing on the device is reachable from the
// internet) and answers only the chat IDs in .env (TELEGRAM_CHAT_ID). /help
// lists the commands; /menu shows buttons. It covers wake-on-LAN machines,
// device info, the event log, campus login, feature switches, notifications
// and any console command (/cmd).
//
// Security: commands that weaken protection, inject input, reach secrets or
// erase evidence (see cli::sensitive) wait for OK on the AuthKey itself.
// TOTP codes are never sent unless "remote codes" is switched on on the
// device (it can't be switched on from Telegram).
//
// Messages from other chats are ignored and logged to serial. With a token
// but no chat ID yet ("finder mode") the device only logs the chat ID of each
// message it receives (serial + event log), so you can copy yours into .env.
//
// The TLS certificate is verified against Telegram's root CA; a failed check
// is reported, never bypassed. The connection stays up next to the web page,
// Proxmox calls and the campus portal's refresh; it hangs up only while a
// hybrid sign-in runs, while the campus network is logged out, or when RAM is
// short, then reconnects.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace telegram {

void init();
void loop();

bool enabled();              // a bot token is set
bool finderMode();           // token set, no chat ID yet
const char* stateStr();
const char* lastError();
long long lastIgnoredChat(); // most recent chat that isn't on the allow-list (0 = none)

// Event notifications: 0 off, 1 important (default), 2 all.
int  notifyLevel();
void setNotifyLevel(int level);
const char* notifyLevelName(int level);

// Whether /code may send TOTP codes. Only the device UI changes it.
bool remoteCodes();
void setRemoteCodes(bool on);

// Whether "allow this browser?" (web page) is also offered here, for when you
// are not near the device. On by default; switching it back on from Telegram
// needs OK on the device. See net/web.h for what such a session can't do.
bool webApprove();
void setWebApprove(bool on);

// Queue a message to every allowed chat.
void notify(const char* text);

// Close the connection now so another TLS user (hybrid tunnel) has the RAM.
void releaseTls();

// Test: verified TLS connection to api.telegram.org (no token needed). Blocks
// a few seconds; describes the result in `out`.
bool ping(char* out, size_t cap);

// Runs a bot command as if the first allowed chat had sent it; replies go to
// the serial console (testing without Telegram).
void simulate(const char* text);

}  // namespace telegram
