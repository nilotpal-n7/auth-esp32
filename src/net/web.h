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
// are bound to the browser's IP. State-changing requests must carry the
// "X-AuthKey: 1" header, which a page on another site cannot add without a
// CORS preflight this server never approves.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace web {

void loop();    // starts the server once WiFi is up, then serves requests

}  // namespace web
