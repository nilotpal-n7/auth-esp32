// =============================================================================
// ui/buttons.h — debounced buttons with short / long press events
// =============================================================================
#pragma once

#include <Arduino.h>

enum class Key : uint8_t {
    None,
    Up, Down, Ok, Left, Right,           // short press (on release)
    UpLong, DownLong, OkLong,            // long press (fires while held)
};

namespace buttons {
void init();
Key  poll();          // one event per call, Key::None if nothing happened
bool anyHeld();
}
