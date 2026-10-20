#include "ui/buttons.h"
#include "config.h"
#include <Bounce2.h>

namespace buttons {

struct Btn {
    Bounce2::Button b;
    uint8_t pin;
    Key shortKey;
    Key longKey;          // Key::None: no long-press action
    bool longFired;
};

static Btn s_btns[] = {
    {Bounce2::Button(), PIN_BTN_UP,    Key::Up,    Key::UpLong,   false},
    {Bounce2::Button(), PIN_BTN_DOWN,  Key::Down,  Key::DownLong, false},
    {Bounce2::Button(), PIN_BTN_OK,    Key::Ok,    Key::OkLong,   false},
    {Bounce2::Button(), PIN_BTN_LEFT,  Key::Left,  Key::None,     false},
    {Bounce2::Button(), PIN_BTN_RIGHT, Key::Right, Key::None,     false},
};

void init() {
    for (auto& b : s_btns) {
        b.b.attach(b.pin, INPUT_PULLUP);
        b.b.interval(BTN_DEBOUNCE_MS);
        b.b.setPressedState(LOW);
    }
}

Key poll() {
    Key ev = Key::None;
    for (auto& b : s_btns) {
        b.b.update();
        if (ev != Key::None) continue;
        if (b.b.pressed()) {
            b.longFired = false;
        } else if (b.b.isPressed() && !b.longFired && b.longKey != Key::None &&
                   b.b.currentDuration() >= BTN_LONG_PRESS_MS) {
            b.longFired = true;
            ev = b.longKey;
        } else if (b.b.released()) {
            if (!b.longFired) ev = b.shortKey;
            b.longFired = false;
        }
    }
    return ev;
}

bool anyHeld() {
    for (auto& b : s_btns) if (b.b.isPressed()) return true;
    return false;
}

}  // namespace buttons
