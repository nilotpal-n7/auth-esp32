// =============================================================================
// cli/cli.h — USB serial console (115200 baud). Type `help`.
// =============================================================================
#pragma once

#include <Arduino.h>

namespace cli {
void init();
void loop();

// Runs one console command line; its console output is appended to `output`
// (used by the Telegram bot's /cmd).
void run(const char* line, String* output);

// True for commands that weaken protection, inject input, reach secrets or
// erase evidence: from Telegram they need OK on the device first.
bool sensitive(const char* line);
}
