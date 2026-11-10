// =============================================================================
// net/web.h — small management web page on the local network
//
//   http://authkey-esp32.local/  (or http://<device IP>/, shown on Device info)
//
// Anyone on the network sees only /api/status (WiFi, campus-login state,
// counts; no names or secrets), which the PC helper polls for its campus
// notifications. Everything else (event log, campus login / logout, TOTP and
// passkey lists, phone sign-in) needs a browser session that was allowed by
// pressing OK on the device. Sessions last 12 hours, are held in RAM only and
// are bound to the browser's IP.
//
// When you are not near the device, the same request can be answered from
// Telegram (your own chat only; the message, the page and the device show the
// same 4-digit code). A session allowed that way can't delete passkeys or
// TOTP accounts, start a phone sign-in or install firmware: those still need
// a press on the device. State-changing requests must carry the
// "X-AuthKey: 1" header, which a page on another site cannot add without a
// CORS preflight this server never approves.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace web {

void loop();    // starts the server once WiFi is up, then serves requests

// Telegram as a second way to answer "allow this browser?". The asker sends
// the prompt (false: not available); remoteDecision() is the answer, false =
// no request with that code is waiting (expired or already answered).
typedef bool (*RemoteAskFn)(const char* ip, unsigned code);
void setRemoteAsker(RemoteAskFn fn);
bool remoteDecision(unsigned code, bool allow);

}  // namespace web
