// =============================================================================
// AuthKey-ESP32 — TOTP generator + FIDO2 security key
//
// Everything runs cooperatively from loop(); NimBLE callbacks only queue work.
// =============================================================================

#include <Arduino.h>
#include <nvs_flash.h>

#include "config.h"
#include "cli/cli.h"
#include "core/approval.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "fido/credentials.h"
#include "fido/ctap2.h"
#include "net/network.h"
#include "net/portal.h"
#include "net/web.h"
#include "totp/totp.h"
#include "transport/ble.h"
#include "transport/hybrid.h"
#include "ui/ui.h"
#include "unlock/unlock.h"

// TLS (hybrid tunnel) and P-256 maths need more than the default 8 KB stack.
SET_LOOP_TASK_STACK_SIZE(16 * 1024);

static void fatal(const char* what) {
    logf("MAIN", "FATAL: %s", what);
    ui::bootStatus(what);
    while (true) delay(1000);
}

static void initNvs() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // Partition layout changed (e.g. first boot after upgrading from v1).
        logf("MAIN", "NVS layout changed, erasing");
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) fatal("NVS init failed");
}

// Why the previous run ended, for the event log ("crash", "power on", ...).
static const char* resetReason() {
    switch (esp_reset_reason()) {
        case ESP_RST_POWERON:  return "power on";
        case ESP_RST_SW:       return "restart";
        case ESP_RST_PANIC:    return "crash";
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT:      return "watchdog";
        case ESP_RST_BROWNOUT: return "brownout";
        case ESP_RST_EXT:      return "reset pin";
        case ESP_RST_DEEPSLEEP:return "wake";
        default:               return "reset";
    }
}

void setup() {
    Serial.begin(115200);
    pinMode(PIN_LED, OUTPUT);
    delay(200);
    logf("MAIN", "%s v%s starting", FW_NAME, FW_VERSION);

    ui::init();
    ui::bootStatus("Starting...");

    initNvs();
    logInit();
    if (!crypto::init()) fatal("Crypto init failed");
    if (!settings::init()) fatal("Settings init failed");
    totp::init();
    creds::init();
    unlock::init();
    ctap::init();

    ui::bootStatus("Starting Bluetooth");
    ble::init();

    ui::bootStatus("Starting WiFi");
    network::init();
    network::setOtaProgressHandler(ui::otaProgress);
    portal::init();

    cli::init();
    logEvent("Boot v" FW_VERSION " (%s)", resetReason());
#ifdef AUTHKEY_TEST_HOOKS
    logEvent("TEST BUILD - insecure");
#endif
    logf("MAIN", "Ready. Type 'help' on the serial console.");
}

void loop() {
    cli::loop();
    logLoop();
    ble::loop();
    network::loop();
    portal::loop();
    if (network::otaActive()) return;   // ArduinoOTA drives the screen itself

    // Hybrid QR text delivered over BLE (tools/qr_bridge.py).
    static char qr[512];
    if (ble::takeProvisioning(qr, sizeof(qr))) hybrid::start(qr);

    hybrid::loop();
    unlock::loop();
    web::loop();
    approval::loop();
    ctap::loop();
    ui::loop();

    // Heartbeat: slow blink normally, fast blink while waiting for the user.
    uint32_t period = ctap::busy() ? 150 : 1000;
    digitalWrite(PIN_LED, (millis() / period) % 2 ? HIGH : LOW);
    delay(2);
}
