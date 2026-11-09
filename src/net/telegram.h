// =============================================================================
// net/telegram.h — Telegram bot for the server wake-up commands
//
// Polls Telegram (long polling: nothing on the device is reachable from the
// internet) and answers only the chat IDs in .env (TELEGRAM_CHAT_ID):
//
//   /wake                send the wake-on-LAN packet, report when the server is up
//   /status              🟢 up / 🔴 down (TCP 8006, then 22)
//   /autowake on|off [min]   wake it when unreachable for N minutes (default off)
//   /setip <ip>          the server's address (DHCP may change it)
//   /help
//
// Messages from other chats are ignored and logged to serial. With a token
// but no chat ID yet ("finder mode") the device only logs the chat ID of each
// message it receives (serial + event log), so you can copy yours into .env.
//
// The TLS certificate is verified against Telegram's root CA; a failed check
// is reported in the log, never bypassed. Only one TLS connection fits in RAM
// next to Bluetooth, so the bot hangs up just before the campus portal's
// scheduled refresh and while a hybrid sign-in runs, then reconnects.
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

// Queue a message to every allowed chat.
void notify(const char* text);

// Close the connection now so another TLS user (hybrid tunnel) has the RAM.
void releaseTls();

// Test: verified TLS connection to api.telegram.org (no token needed). Blocks
// a few seconds; describes the result in `out`.
bool ping(char* out, size_t cap);

}  // namespace telegram
