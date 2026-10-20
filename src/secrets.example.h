// =============================================================================
// secrets.example.h — copy to secrets.h (git-ignored) and fill in.
// =============================================================================
#pragma once

// WiFi networks imported into the device's saved-network list on first boot
// (or after `wifi reset`). More can be added later over the serial console:
//   wifi add <ssid> <password>
#define SECRET_WIFI_NETWORKS      \
    { "MyHomeWiFi", "password" }, \
    { "PhoneHotspot", "password" },

// Password required for over-the-air firmware updates. Leave empty ("") to
// disable OTA entirely — strongly recommended unless you need it, because
// anyone who can flash the firmware can read every key on the device.
#define SECRET_OTA_PASSWORD ""
