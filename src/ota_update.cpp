#include "ota_update.h"
#include "config.h"
#include "ui.h"
#include <ArduinoOTA.h>
#include <WiFi.h>

static bool s_isUpdating = false;

void otaInit() {
#if ENABLE_OTA
    ArduinoOTA.setHostname(BLE_DEVICE_NAME);

    ArduinoOTA.onStart([]() {
        s_isUpdating = true;
        String type;
        if (ArduinoOTA.getCommand() == U_FLASH) {
            type = "sketch";
        } else { // U_SPIFFS
            type = "filesystem";
        }
        Serial.println("\n[OTA] Start updating " + type);
        uiDrawMessage("OTA Update", "Starting...", "");
    });

    ArduinoOTA.onEnd([]() {
        Serial.println("\n[OTA] Update Finished!");
        uiDrawMessage("OTA Update", "Success! Rebooting...", "");
    });

    ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
        Serial.printf("[OTA] Progress: %u%%\r", (progress / (total / 100)));
        uiDrawOTAProgress(progress, total);
    });

    ArduinoOTA.onError([](ota_error_t error) {
        s_isUpdating = false;
        Serial.printf("[OTA] Error[%u]: ", error);
        if (error == OTA_AUTH_ERROR) Serial.println("Auth Failed");
        else if (error == OTA_BEGIN_ERROR) Serial.println("Begin Failed");
        else if (error == OTA_CONNECT_ERROR) Serial.println("Connect Failed");
        else if (error == OTA_RECEIVE_ERROR) Serial.println("Receive Failed");
        else if (error == OTA_END_ERROR) Serial.println("End Failed");
        uiDrawMessage("OTA Error", "Update Failed!", "");
        delay(3000);
    });

    ArduinoOTA.begin();
    Serial.println("[OTA] Service initialized.");
#endif
}

void otaLoop() {
#if ENABLE_OTA
    if (WiFi.status() == WL_CONNECTED) {
        ArduinoOTA.handle();
    }
#endif
}

bool otaIsUpdating() {
    return s_isUpdating;
}
