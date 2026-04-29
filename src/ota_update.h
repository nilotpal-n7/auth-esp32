#pragma once

// Initialize the ArduinoOTA service.
void otaInit();

// Must be called continuously in loop() to process incoming updates.
void otaLoop();

// Returns true if an OTA update is currently in progress.
bool otaIsUpdating();
