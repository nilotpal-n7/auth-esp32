// =============================================================================
// ui.cpp — Terminal-Style OLED Rendering Engine
// =============================================================================

#include "ui.h"
#include <U8g2lib.h>
#include <Wire.h>

// Hardware I2C OLED — SSD1306 128x64
// We use the default hardware I2C constructor because GPIO 21 (SDA) and GPIO 22 (SCL) are the ESP32 defaults.
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, U8X8_PIN_NONE);

// =============================================================================
// HELPER — Draw status bar at top of screen
// =============================================================================
static void drawStatusBar(bool autoAllow, bool bleConnected, bool wifiConnected, const char* timeStr) {
    u8g2.setFont(u8g2_font_5x7_tr);

    if (autoAllow) {
        u8g2.drawStr(0, 7, "[A]");
    } else {
        u8g2.drawStr(0, 7, "[M]");
    }

    // Time in center
    if (timeStr && strlen(timeStr) > 0) {
        int tw = u8g2.getStrWidth(timeStr);
        u8g2.drawStr((SCREEN_WIDTH - tw) / 2, 7, timeStr);
    }

    // WiFi icon
    if (wifiConnected) {
        u8g2.drawStr(90, 7, "W");
    }

    // BLE indicator on the right
    if (bleConnected) {
        u8g2.drawStr(104, 7, "BLE*");
    } else {
        u8g2.drawStr(108, 7, "BLE");
    }

    // Separator line
    u8g2.drawHLine(0, STATUS_BAR_HEIGHT, SCREEN_WIDTH);
}

// =============================================================================
// HELPER — Draw navigation bar at bottom
// =============================================================================
static void drawNavBar(const char* leftLabel, const char* rightLabel) {
    u8g2.drawHLine(0, SCREEN_HEIGHT - NAV_BAR_HEIGHT, SCREEN_WIDTH);
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(2, SCREEN_HEIGHT - 2, leftLabel);

    // Right-align the right label
    int rw = u8g2.getStrWidth(rightLabel);
    u8g2.drawStr(SCREEN_WIDTH - rw - 2, SCREEN_HEIGHT - 2, rightLabel);
}

// =============================================================================
// HELPER — Draw Pagination Dots
// =============================================================================
static void drawPaginationDots(int currentPage, int totalPages) {
    if (totalPages <= 1) return;
    
    int dotSpacing = 8;
    int totalWidth = (totalPages - 1) * dotSpacing;
    int startX = (SCREEN_WIDTH - totalWidth) / 2;
    int y = SCREEN_HEIGHT - 4;
    
    for (int i = 0; i < totalPages; i++) {
        if (i == currentPage) {
            u8g2.drawDisc(startX + (i * dotSpacing), y - 1, 2);
        } else {
            u8g2.drawPixel(startX + (i * dotSpacing), y - 1);
        }
    }
}

// =============================================================================
// HELPER — Draw a progress bar
// =============================================================================
static void drawProgressBar(int x, int y, int w, int h, uint8_t value, uint8_t maxVal) {
    u8g2.drawFrame(x, y, w, h);
    int fillW = (int)((float)value / maxVal * (w - 2));
    if (fillW > 0) {
        u8g2.drawBox(x + 1, y + 1, fillW, h - 2);
    }
}

// =============================================================================
// PUBLIC API
// =============================================================================

void uiInit() {
    Wire.begin(PIN_SDA, PIN_SCL); // Explicitly initialize the I2C bus
    u8g2.begin();
    u8g2.setContrast(255);  // Max brightness
    u8g2.clearBuffer();
    Serial.println("[UI] OLED initialized.");
}

void uiDrawBoot() {
    u8g2.clearBuffer();

    // Title (Yellow region: Y <= 15)
    u8g2.setFont(u8g2_font_ncenB10_tr);
    const char* title = "AuthKey";
    int tw = u8g2.getStrWidth(title);
    u8g2.drawStr((SCREEN_WIDTH - tw) / 2, 14, title);

    // Subtitle (Blue region: Y >= 16)
    u8g2.setFont(u8g2_font_5x7_tr);
    const char* sub = "ESP32 Authenticator";
    int sw = u8g2.getStrWidth(sub);
    u8g2.drawStr((SCREEN_WIDTH - sw) / 2, 28, sub);

    // Version
    u8g2.setFont(u8g2_font_4x6_tr);
    u8g2.drawStr(42, 42, "v1.0.0-alpha");

    // Bottom line
    u8g2.drawHLine(20, 48, 88);

    u8g2.sendBuffer();
}

void uiDrawSyncing(const char* statusText) {
    u8g2.clearBuffer();

    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(10, 13, "Time Sync");

    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(10, 28, statusText);

    // Animated dots (simple frame-based)
    static uint8_t dotFrame = 0;
    char dots[4] = {0};
    for (int i = 0; i <= (dotFrame % 3); i++) dots[i] = '.';
    u8g2.drawStr(10, 38, dots);
    dotFrame++;

    u8g2.sendBuffer();
}

void uiDrawInitBLE() {
    u8g2.clearBuffer();

    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(15, 13, "Starting BLE");

    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(15, 28, "FIDO2 Service...");

    u8g2.sendBuffer();
}

void uiDrawTOTP(const char* accountName, const char* totpCode,
                uint8_t secondsRemaining, int accountIndex, int accountTotal,
                bool autoAllow, bool bleConnected, bool wifiConnected, const char* timeStr,
                int currentPage, int totalPages) {
    u8g2.clearBuffer();

    // --- Status Bar (Auto & BLE only) ---
    drawStatusBar(autoAllow, bleConnected, false, nullptr);

    // --- Account name ---
    u8g2.setFont(u8g2_font_5x7_tr);
    char accountLabel[40];
    snprintf(accountLabel, sizeof(accountLabel), "%s (%d/%d)", accountName, accountIndex + 1, accountTotal);
    u8g2.drawStr(4, 26, accountLabel);

    // --- Large TOTP code ---
    u8g2.setFont(u8g2_font_ncenB14_tr);
    int codeWidth = u8g2.getStrWidth(totpCode);
    u8g2.drawStr((SCREEN_WIDTH - codeWidth) / 2, 44, totpCode);

    // --- Countdown progress bar ---
    drawProgressBar(4, 48, 120, 5, secondsRemaining, TOTP_PERIOD);

    // --- Pagination ---
    drawPaginationDots(currentPage, totalPages);

    u8g2.sendBuffer();
}

void uiDrawFidoPrompt(const char* requestType, const char* rpId,
                      bool autoAllow, uint8_t timeoutSeconds) {
    u8g2.clearBuffer();

    // --- Status Bar ---
    drawStatusBar(autoAllow, true, false, nullptr);

    // --- Request type ---
    u8g2.setFont(u8g2_font_ncenB08_tr);
    char header[32];
    snprintf(header, sizeof(header), "%s Request", requestType);
    int hw = u8g2.getStrWidth(header);
    u8g2.drawStr((SCREEN_WIDTH - hw) / 2, 13, header); // Yellow

    // --- RP Domain ---
    u8g2.setFont(u8g2_font_6x10_tr);
    int rpw = u8g2.getStrWidth(rpId);
    int rpx = (SCREEN_WIDTH - rpw) / 2;
    if (rpx < 2) rpx = 2;
    u8g2.drawStr(rpx, 28, rpId); // Blue

    // --- Timeout bar ---
    drawProgressBar(4, 40, 120, 4, timeoutSeconds, 30);

    // --- Navigation ---
    if (autoAllow) {
        drawNavBar("", "AUTO-SIGN");
    } else {
        drawNavBar("", "[APPROVE]");
    }

    u8g2.sendBuffer();
}

void uiDrawMessage(const char* title, const char* line1, const char* line2) {
    u8g2.clearBuffer();

    u8g2.setFont(u8g2_font_ncenB08_tr);
    int tw = u8g2.getStrWidth(title);
    u8g2.drawStr((SCREEN_WIDTH - tw) / 2, 13, title); // Yellow

    u8g2.setFont(u8g2_font_5x7_tr);
    if (line1) {
        u8g2.drawStr(8, 28, line1); // Blue
    }
    if (line2) {
        u8g2.drawStr(8, 40, line2); // Blue
    }

    u8g2.sendBuffer();
}

void uiDrawOTAProgress(unsigned int progress, unsigned int total) {
    u8g2.clearBuffer();
    
    // Title
    u8g2.setFont(u8g2_font_ncenB08_tr);
    const char* title = "OTA Updating...";
    int titleW = u8g2.getStrWidth(title);
    u8g2.drawStr((SCREEN_WIDTH - titleW) / 2, 13, title); // Yellow
    
    int percent = (total > 0) ? (progress * 100 / total) : 0;
    
    // Draw progress bar frame
    u8g2.drawFrame(10, 35, 108, 12);
    
    // Draw progress bar fill
    int barWidth = (104 * percent) / 100;
    if (barWidth > 0) {
        u8g2.drawBox(12, 37, barWidth, 8);
    }
    
    // Draw percentage text
    char buf[16];
    snprintf(buf, sizeof(buf), "%d%%", percent);
    u8g2.setFont(u8g2_font_5x7_tr);
    int textW = u8g2.getStrWidth(buf);
    u8g2.drawStr((SCREEN_WIDTH - textW) / 2, 58, buf);
    
    u8g2.sendBuffer();
}
void uiDrawSettingsMenu(int selectedIndex, bool autoAllow, const char* ip, const char* mac,
                        int currentPage, int totalPages) {
    u8g2.clearBuffer();
    
    // Title
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(5, 12, "Settings");
    u8g2.drawHLine(0, 15, SCREEN_WIDTH);
    
    u8g2.setFont(u8g2_font_5x7_tr);
    
    // Options
    const char* opt1 = autoAllow ? "1. Auto-Approve: ON" : "1. Auto-Approve: OFF";
    const char* opt2 = "2. View IP Address";
    const char* opt3 = "3. View MAC Address";
    
    const char* options[] = { opt1, opt2, opt3 };
    
    for (int i = 0; i < 3; i++) {
        int y = 26 + (i * 10);
        if (i == selectedIndex) {
            u8g2.drawBox(0, y - 8, SCREEN_WIDTH, 10);
            u8g2.setDrawColor(0); // Invert text
        }
        
        if (i == 1 && selectedIndex == 1) {
            u8g2.drawStr(4, y, ip);
        } else if (i == 2 && selectedIndex == 2) {
            u8g2.drawStr(4, y, mac);
        } else {
            u8g2.drawStr(4, y, options[i]);
        }
        
        if (i == selectedIndex) {
            u8g2.setDrawColor(1); // Restore normal text
        }
    }
    
    // --- Pagination ---
    drawPaginationDots(currentPage, totalPages);
    
    u8g2.sendBuffer();
}

#include "logger.h"

void uiDrawIntroPage(const char* timeStr, bool wifiConnected, bool bleConnected, int currentPage, int totalPages) {
    u8g2.clearBuffer();
    
    drawStatusBar(false, bleConnected, wifiConnected, timeStr);
    
    u8g2.setFont(u8g2_font_ncenB10_tr);
    const char* title = "ESP32-AUTH";
    int tw = u8g2.getStrWidth(title);
    u8g2.drawStr((SCREEN_WIDTH - tw) / 2, 35, title); // Blue
    
    u8g2.setFont(u8g2_font_5x7_tr);
    const char* sub = "Secure FIDO2 + TOTP";
    int sw = u8g2.getStrWidth(sub);
    u8g2.drawStr((SCREEN_WIDTH - sw) / 2, 50, sub); // Blue
    
    drawPaginationDots(currentPage, totalPages);
    u8g2.sendBuffer();
}

void uiDrawLogsPage(int currentPage, int totalPages) {
    u8g2.clearBuffer();
    
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(5, 12, "Recent Logs");
    u8g2.drawHLine(0, 15, SCREEN_WIDTH);
    
    u8g2.setFont(u8g2_font_4x6_tr);
    int count = logGetCount();
    
    // Display up to 6 most recent logs that fit on screen
    int displayCount = (count > 6) ? 6 : count;
    int startIndex = count - displayCount;
    
    for (int i = 0; i < displayCount; i++) {
        const char* msg = logGetMessage(startIndex + i);
        u8g2.drawStr(0, 24 + (i * 6), msg);
    }
    
    drawPaginationDots(currentPage, totalPages);
    u8g2.sendBuffer();
}

#include "wifi_manager.h"
#include <WiFi.h>

void uiDrawConnectivityPage(ConnPageMode mode, int selectedIndex,
                            int currentPage, int totalPages) {
    u8g2.clearBuffer();
    
    // Header in yellow region
    u8g2.setFont(u8g2_font_ncenB08_tr);
    u8g2.drawStr(5, 12, "Connectivity");
    u8g2.drawHLine(0, 15, SCREEN_WIDTH);
    
    u8g2.setFont(u8g2_font_4x6_tr);
    
    switch (mode) {
    case CONN_MODE_OVERVIEW: {
        // Show saved networks and options
        int savedCount = wifiMgrSavedCount();
        int totalItems = savedCount + 2; // +1 for "Scan WiFi", +1 for BLE status
        
        // Draw items (fit ~6 lines in blue region)
        int maxVisible = 6;
        int scrollOffset = 0;
        if (selectedIndex >= maxVisible) {
            scrollOffset = selectedIndex - maxVisible + 1;
        }
        
        for (int i = 0; i < maxVisible && (i + scrollOffset) < totalItems; i++) {
            int itemIdx = i + scrollOffset;
            int y = 24 + (i * 7);
            
            if (itemIdx == selectedIndex) {
                u8g2.drawBox(0, y - 6, SCREEN_WIDTH, 7);
                u8g2.setDrawColor(0);
            }
            
            if (itemIdx < savedCount) {
                // Saved WiFi entry
                WifiEntry entry;
                wifiMgrGetSaved(itemIdx, &entry);
                char line[34];
                
                // Show connection status indicator
                bool isConnected = (WiFi.status() == WL_CONNECTED && 
                                   strcmp(WiFi.SSID().c_str(), entry.ssid) == 0);
                snprintf(line, sizeof(line), "%s %s", 
                         isConnected ? ">" : " ", entry.ssid);
                u8g2.drawStr(0, y, line);
            } else if (itemIdx == savedCount) {
                // Scan WiFi option
                u8g2.drawStr(0, y, "[Scan WiFi]");
            } else {
                // BLE status
                u8g2.drawStr(0, y, "[BLE: Active]");
            }
            
            if (itemIdx == selectedIndex) {
                u8g2.setDrawColor(1);
            }
        }
        break;
    }
    
    case CONN_MODE_SAVED_MENU: {
        // Show sub-menu for the selected saved network
        const char* pendingSSID = wifiMgrGetPendingSSID();
        
        u8g2.setFont(u8g2_font_5x7_tr);
        char ssidLine[34];
        snprintf(ssidLine, sizeof(ssidLine), "%.22s", pendingSSID);
        u8g2.drawStr(4, 24, ssidLine);
        u8g2.drawHLine(0, 26, SCREEN_WIDTH);
        
        const char* menuItems[] = { "Connect", "Change Password", "Forget Network" };
        
        for (int i = 0; i < 3; i++) {
            int y = 36 + (i * 10);
            if (i == selectedIndex) {
                u8g2.drawBox(0, y - 8, SCREEN_WIDTH, 10);
                u8g2.setDrawColor(0);
            }
            u8g2.drawStr(8, y, menuItems[i]);
            if (i == selectedIndex) {
                u8g2.setDrawColor(1);
            }
        }
        break;
    }
    
    case CONN_MODE_SCANNING: {
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(20, 35, "Scanning WiFi...");
        
        // Animated dots
        static uint8_t frame = 0;
        char dots[4] = {0};
        for (int i = 0; i <= (frame % 3); i++) dots[i] = '.';
        u8g2.drawStr(100, 35, dots);
        frame++;
        break;
    }
    
    case CONN_MODE_SCAN_RESULTS: {
        WifiScanResult results[WIFIMGR_MAX_SCAN];
        int count = wifiMgrGetScanResults(results, WIFIMGR_MAX_SCAN);
        
        if (count == 0) {
            u8g2.setFont(u8g2_font_5x7_tr);
            u8g2.drawStr(15, 35, "No networks found");
        } else {
            int maxVisible = 6;
            int scrollOffset = 0;
            if (selectedIndex >= maxVisible) {
                scrollOffset = selectedIndex - maxVisible + 1;
            }
            
            for (int i = 0; i < maxVisible && (i + scrollOffset) < count; i++) {
                int itemIdx = i + scrollOffset;
                int y = 24 + (i * 7);
                
                if (itemIdx == selectedIndex) {
                    u8g2.drawBox(0, y - 6, SCREEN_WIDTH, 7);
                    u8g2.setDrawColor(0);
                }
                
                char line[34];
                snprintf(line, sizeof(line), "%s%s %ddB",
                         results[itemIdx].encrypted ? "*" : " ",
                         results[itemIdx].ssid,
                         results[itemIdx].rssi);
                u8g2.drawStr(0, y, line);
                
                if (results[itemIdx].saved) {
                    u8g2.drawStr(120, y, "S");
                }
                
                if (itemIdx == selectedIndex) {
                    u8g2.setDrawColor(1);
                }
            }
        }
        break;
    }
    
    case CONN_MODE_WAIT_PASSWORD: {
        u8g2.setFont(u8g2_font_5x7_tr);
        
        const char* pendingSSID = wifiMgrGetPendingSSID();
        char ssidLine[34];
        snprintf(ssidLine, sizeof(ssidLine), "Net: %.20s", pendingSSID);
        u8g2.drawStr(4, 26, ssidLine);
        
        u8g2.drawStr(4, 38, "Enter password via");
        u8g2.drawStr(4, 48, "Serial Monitor...");
        
        // Blinking cursor
        static bool blink = false;
        blink = !blink;
        if (blink) {
            u8g2.drawStr(110, 48, "_");
        }
        break;
    }
    
    case CONN_MODE_CONNECTING: {
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(20, 35, "Connecting...");
        break;
    }
    }
    
    drawPaginationDots(currentPage, totalPages);
    u8g2.sendBuffer();
}
