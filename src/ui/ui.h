// =============================================================================
// ui/ui.h — OLED user interface and on-device approvals
//
// Controls:   UP / DOWN       move / change
//             OK              select / approve
//             OK (hold)       menu / back / submit
//             DOWN on prompts deny
//             LEFT / RIGHT    optional back / menu shortcuts
// =============================================================================
#pragma once

#include <Arduino.h>

namespace ui {

void init();
void bootStatus(const char* line);
void loop();
void otaProgress(unsigned done, unsigned total);

}  // namespace ui
