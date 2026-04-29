# AuthKey-ESP32: Hardware Authenticator

AuthKey-ESP32 is a standalone, ESP32-based hardware authenticator supporting **FIDO2 (caBLE v2)** and **TOTP**. It features a physical OLED UI, tactile buttons for manual approvals, and seamless Over-The-Air (OTA) firmware updates.

## 🚀 Features
* **FIDO2 caBLE v2 Tunnel:** Acts as a roaming authenticator via a WebSocket tunnel, supporting Windows Hello and Chromium-based browsers natively.
* **TOTP Generator:** Locally generates 6-digit Time-Based One-Time Passwords with visual countdowns.
* **Multi-WiFi Fallback:** Automatically scans and connects to configured WiFi networks to sync the NTP clock for accurate TOTP generation.
* **Settings Menu:** On-device UI to toggle Auto-Approve, view IP/MAC addresses, and monitor network status.
* **OTA Updates:** Flash new firmware wirelessly over WiFi.

## 🛠 Hardware Setup
* **ESP32** (e.g., ESP32-WROOM-32 / ESP32-DevKit)
* **SSD1306 128x64 I2C OLED Display**
  * SDA -> GPIO 21
  * SCL -> GPIO 22
* **3x Push Buttons** (Active LOW, internal pull-ups enabled)
  * UP -> GPIO 25
  * DOWN -> GPIO 26
  * APPROVE -> GPIO 27

---

## 💻 Uploading Firmware (PlatformIO)

### 1. Initial Flash (USB)
The very first time you flash the ESP32, you **must** use a USB cable. This installs the base firmware and the OTA service.
```bash
# Compile and upload via USB, then open the serial monitor
pio run -t upload
pio device monitor
```
*Note: Make sure your WiFi credentials are set in `src/config.h` before uploading so the ESP32 can connect to your network.*

### 2. Over-The-Air (OTA) Updates
Once the ESP32 is running and connected to WiFi, you can flash subsequent updates entirely wirelessly! The blue heartbeat LED (GPIO 2) will stay solid ON during the update process, and the OLED will display a live progress bar.

#### Option A: Upload via IP Address (Most Reliable)
Find your ESP32's IP address (visible in the device's Settings Menu).
```bash
pio run -t upload --upload-port 192.168.1.xxx
```

#### Option B: Upload via mDNS (.local)
If your router and OS support mDNS, you can use the hostname directly.
```bash
pio run -t upload --upload-port AuthKey-ESP32.local
```

#### Option C: Make OTA the Default
If you want to use OTA every time you type `pio run -t upload`, add these two lines to the bottom of your `platformio.ini`:
```ini
upload_protocol = espota
upload_port = AuthKey-ESP32.local   # Or use the IP address here
```
*(Warning: The `pio device monitor` command still requires a USB connection to view serial logs.)*

---

## 📱 UI & Usage Guide

### Main Screen (TOTP)
* Use the **UP** and **DOWN** buttons to cycle through your stored TOTP accounts.
* The top status bar displays the current time, auto/manual mode `[A]/[M]`, WiFi connection status `W`, and BLE advertisement status `BLE*`.

### Settings Menu
* From the main screen, press and hold the **APPROVE** button for 1.5 seconds.
* Navigate with **UP/DOWN** and select with **APPROVE**.
* **Auto-Approve:** Toggle whether FIDO2 requests are automatically signed or if they require a physical button press.
* **View IP / MAC:** Dynamically view network details for OTA uploads.

### FIDO2 Login
1. On your PC, select "Use phone or tablet" during a passkey login.
2. Scan the generated QR code with a generic QR scanner app on your phone, or let the ESP32 automatically broadcast its BLE advertisement (`BLE*`).
3. Your PC will securely tunnel the request to the ESP32.
4. Press the **APPROVE** button when prompted on the OLED!
