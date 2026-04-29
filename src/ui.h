// =============================================================================
// ui.h — Terminal-Style OLED Rendering Engine
// =============================================================================
#pragma once

#include <Arduino.h>
#include "config.h"

// Initialize the OLED display (U8g2).
void uiInit();

// Draw the boot splash screen.
void uiDrawBoot();

// Draw the "Syncing time..." screen with WiFi status.
void uiDrawSyncing(const char* statusText);

// Draw the "Initializing BLE..." screen.
void uiDrawInitBLE();

// Draw the main TOTP view (Page 1)
void uiDrawTOTP(const char* accountName, const char* totpCode,
                uint8_t secondsRemaining, int accountIndex, int accountTotal,
                bool autoAllow, bool bleConnected, bool wifiConnected, const char* timeStr,
                int currentPage, int totalPages);

// Draw the Settings menu (Page 2)
void uiDrawSettingsMenu(int selectedIndex, bool autoAllow, const char* ip, const char* mac,
                        int currentPage, int totalPages);

// Draw the Intro screen (Page 0)
void uiDrawIntroPage(const char* timeStr, bool wifiConnected, bool bleConnected, int currentPage, int totalPages);

// Draw the Logs screen (Page 3)
void uiDrawLogsPage(int currentPage, int totalPages);

// Draw the Connectivity screen (Page 4)
// mode: current sub-mode (overview, scanning, scan results, waiting for password, connecting)
// selectedIndex: currently highlighted item
// Pass scan results and saved entries via wifi_manager API internally.
#include "wifi_manager.h"
void uiDrawConnectivityPage(ConnPageMode mode, int selectedIndex,
                            int currentPage, int totalPages);

// Draw the FIDO2 approval prompt.
void uiDrawFidoPrompt(const char* requestType, const char* rpId,
                      bool autoAllow, uint8_t timeoutSeconds);

// Draw a generic message screen.
void uiDrawMessage(const char* title, const char* line1, const char* line2 = nullptr);

// Draw OTA Update progress.
void uiDrawOTAProgress(unsigned int progress, unsigned int total);
