// =============================================================================
// buttons.cpp — Debounced Button Input with Long-Press Detection
// =============================================================================

#include "buttons.h"
#include "config.h"
#include <Bounce2.h>

static Bounce2::Button s_btnUp    = Bounce2::Button();
static Bounce2::Button s_btnDown  = Bounce2::Button();
static Bounce2::Button s_btnApprove = Bounce2::Button();
static Bounce2::Button s_btnLeft  = Bounce2::Button();
static Bounce2::Button s_btnRight = Bounce2::Button();

void buttonsInit() {
    // UP button — debounced, internal pull-up, active LOW
    s_btnUp.attach(PIN_BTN_UP, INPUT_PULLUP);
    s_btnUp.interval(BTN_DEBOUNCE_MS);
    s_btnUp.setPressedState(LOW);

    // DOWN button
    s_btnDown.attach(PIN_BTN_DOWN, INPUT_PULLUP);
    s_btnDown.interval(BTN_DEBOUNCE_MS);
    s_btnDown.setPressedState(LOW);

    // APPROVE button
    s_btnApprove.attach(PIN_BTN_APPROVE, INPUT_PULLUP);
    s_btnApprove.interval(BTN_DEBOUNCE_MS);
    s_btnApprove.setPressedState(LOW);
    
    // LEFT button
    s_btnLeft.attach(PIN_BTN_LEFT, INPUT_PULLUP);
    s_btnLeft.interval(BTN_DEBOUNCE_MS);
    s_btnLeft.setPressedState(LOW);
    
    // RIGHT button
    s_btnRight.attach(PIN_BTN_RIGHT, INPUT_PULLUP);
    s_btnRight.interval(BTN_DEBOUNCE_MS);
    s_btnRight.setPressedState(LOW);
}

ButtonEvent buttonsUpdate() {
    s_btnUp.update();
    s_btnDown.update();
    s_btnApprove.update();
    s_btnLeft.update();
    s_btnRight.update();

    if (s_btnUp.pressed()) {
        return BTN_UP_PRESSED;
    }
    if (s_btnDown.pressed()) {
        return BTN_DOWN_PRESSED;
    }
    if (s_btnLeft.pressed()) {
        return BTN_LEFT_PRESSED;
    }
    if (s_btnRight.pressed()) {
        return BTN_RIGHT_PRESSED;
    }
    if (s_btnApprove.pressed()) {
        return BTN_APPROVE_SHORT;
    }

    return BTN_NONE;
}
