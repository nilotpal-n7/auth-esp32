// =============================================================================
// net/portal.h - IITG FortiGate captive-portal auto-login + keepalive.
//
// The campus firewall (agnigarh.iitg.ac.in:1442) ends the session after a
// while unless it is refreshed. With IITG credentials in .env this logs in by
// itself (GET /login? for a fresh form, POST it), then refreshes the session
// via /keepalive?<magic> so the network behind the router stays online. IITG
// suggests students run exactly this kind of keepalive helper.
//
// Behind a NAT router every device shares one firewall session, so the
// device "owning" the session (logging in itself) keeps everyone online.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace portal {

void init();
void loop();

bool haveCredentials();      // IITG_USERNAME / IITG_PASSWORD set at build time
bool enabled();              // automatic login + keepalive (persisted)
void setEnabled(bool on);
bool paused();               // logged out by hand: no auto login until "login now"

// "off" | "no credentials" | "paused" | "offline" | "logging in" | "online" |
// "limit reached" | "login failed"
const char* stateStr();
bool online();
bool ownsSession();          // we hold the session magic (can keep it alive / log out)
const char* user();
const char* lastResult();    // last outcome, e.g. "logged in", "wrong password?"
uint32_t secondsToNext();    // until the next refresh / retry
int logins();                // successful logins this boot
int keepalives();            // successful refreshes this boot

void loginNow();             // log in now (also when already online) and resume auto
bool logout();               // end the session and pause auto login; false if no session owned

}  // namespace portal
