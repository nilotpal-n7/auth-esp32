#include "core/approval.h"
#include "config.h"
#include "core/log.h"
#include "core/settings.h"

namespace approval {

static Request s_req;
static bool    s_active = false;
static DoneFn  s_done = nullptr;
static void*   s_ctx = nullptr;

static void finish(bool ok) {
    DoneFn done = s_done;
    void* ctx = s_ctx;
    s_active = false;
    s_done = nullptr;
    if (done) done(ok, ctx);
}

bool ask(const char* title, const char* detail, const char* hint, bool needPin, DoneFn done, void* ctx) {
    if (s_active) return false;
    memset(&s_req, 0, sizeof(s_req));
    strlcpy(s_req.title, title, sizeof(s_req.title));
    strlcpy(s_req.detail, detail ? detail : "", sizeof(s_req.detail));
    strlcpy(s_req.hint, hint ? hint : "", sizeof(s_req.hint));
    s_req.needPin = needPin && settings::pinIsSet();
    s_req.startedMs = millis();
    s_done = done;
    s_ctx = ctx;
    s_active = true;
    return true;
}

const Request* pending() { return s_active ? &s_req : nullptr; }

void approve() {
    if (s_active && !s_req.needPin) finish(true);
}

void deny() {
    if (s_active) finish(false);
}

bool submitPin(const char* pin) {
    if (!s_active || !s_req.needPin) return false;
    if (settings::pinVerify(pin)) {
        s_req.needPin = false;
        finish(true);
        return true;
    }
    if (settings::pinRetries() == 0) {
        logEvent("PIN blocked");
        finish(false);
    }
    return false;
}

#ifdef AUTHKEY_TEST_HOOKS
void forceApprove() {
    if (s_active) finish(true);
}
#endif

void loop() {
    if (s_active && millis() - s_req.startedMs > FIDO_USER_TIMEOUT_MS) {
        logf("APPROVE", "'%s' timed out", s_req.title);
        finish(false);
    }
}

}  // namespace approval
