// =============================================================================
// buttons.h — Debounced Button Input with Long-Press Detection
// =============================================================================
#pragma once

#include <Arduino.h>

// Button event types returned each loop iteration
enum ButtonEvent {
    BTN_NONE,
    BTN_UP_PRESSED,
    BTN_DOWN_PRESSED,
    BTN_LEFT_PRESSED,
    BTN_RIGHT_PRESSED,
    BTN_APPROVE_SHORT,
};

// Initialize all three buttons with debouncing.
void buttonsInit();

// Call every loop iteration. Returns the highest-priority event that occurred.
ButtonEvent buttonsUpdate();
