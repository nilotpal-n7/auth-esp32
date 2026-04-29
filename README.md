<description><![CDATA[# 🔐 ESP32 Hardware Authenticator

> **Standalone offline TOTP code generator + BLE FIDO2/WebAuthn security key with hardware Auto-Allow override.**

A dedicated ESP32 device that generates time-based one-time passwords (TOTP) and acts as a Bluetooth Low Energy FIDO2 security key — no phone, no cloud, no trust required. Built with PlatformIO, NimBLE, and raw mbedTLS cryptography.

---

## ✨ Features

| Feature                     | Description                                                                                                 |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| **🔢 TOTP Generator**       | RFC 6238 compliant 6-digit codes via HMAC-SHA1 (mbedTLS). Compatible with Google Authenticator, Authy, etc. |
| **🔑 BLE FIDO2 Key**        | Full CTAP2 authenticator over Bluetooth. Registers and authenticates passkeys for websites.                 |
| **⚡ Auto-Allow Mode**      | Hardware toggle to instantly approve BLE login requests without button press.                               |
| **📟 Terminal OLED UI**     | Crisp 128×64 display with status bar, large TOTP codes, countdown bar, and FIDO2 prompts.                   |
| **🔒 NVS Credential Store** | Stores ~200 FIDO2 passkeys + 20 TOTP accounts in non-volatile flash. Survives reboots.                      |
| **📡 NTP Time Sync**        | Multi-WiFi fallback — tries each configured network in order, syncs UTC, then disconnects to free RAM.      |
| **🎛️ Hardware Debouncing**  | Flawless button input via Bounce2 with 15ms debounce and long-press detection.                              |
| **🔋 Power Efficient**      | WiFi is killed after time sync. NimBLE uses minimal memory. Single BLE connection.                          |

---

## 🔌 Circuit Diagram — Full 30-Pin Pinout

![ESP32 Hardware Authenticator — Full Pinout & Circuit Diagram](./circuit.png)

### Complete ESP32 DevKit V1 Pin Map (30 Pins)

````
                    ┌──────────────────┐
                    │  ESP32-WROOM-32  │
                    │   DevKit V1      │
                    │                  │
  OLED VCC ← RED ──┤ 3V3          VIN ├── 5V Input (USB)
  OLED/BTN GND ────┤ GND          GND ├── Ground
                    ├ GPIO 15    GPIO 13├
   Built-in LED ───┤ GPIO 2     GPIO 12├
                    ├ GPIO 4     GPIO 14├
            RX2 ───┤ GPIO 16    GPIO 27├── CYAN → BTN APPROVE
            TX2 ───┤ GPIO 17    GPIO 26├── ORANGE → BTN DOWN
                    ├ GPIO 5     GPIO 25├── GREEN → BTN UP
       VSPI SCK ───┤ GPIO 18    GPIO 33├── ADC1_5
      VSPI MISO ───┤ GPIO 19    GPIO 32├── ADC1_4
 OLED SDA ← BLUE ──┤ GPIO 21    GPIO 35├── INPUT ONLY
            RX0 ───┤ GPIO 3     GPIO 34├── INPUT ONLY
            TX0 ───┤ GPIO 1   VN/GPIO39├── INPUT ONLY
OLED SCL ← YELLOW ─┤ GPIO 22  VP/GPIO36├── INPUT ONLY
      VSPI MOSI ───┤ GPIO 23        EN ├── Enable/Reset
                    │      [USB-C]     │
                    └──────────────────┘

---

### Interactive Wiring Schematic

```mermaid
graph LR
    subgraph ESP32 [ESP32-WROOM-32]
        3V3((3V3))
        GND((GND))
        GND2((GND))
        P21((GPIO 21))
        P22((GPIO 22))
        P25((GPIO 25))
        P26((GPIO 26))
        P27((GPIO 27))
    end

    subgraph OLED [0.96 OLED Display]
        O_VCC((VCC))
        O_GND((GND))
        O_SDA((SDA))
        O_SCL((SCL))
    end

    subgraph BTN_UP [UP Button]
        U_P1((Leg 1))
        U_P2((Leg 2))
    end

    subgraph BTN_DOWN [DOWN Button]
        D_P1((Leg 1))
        D_P2((Leg 2))
    end

    subgraph BTN_APP [APPROVE Button]
        A_P1((Leg 1))
        A_P2((Leg 2))
    end

    %% Power connections
    3V3 ---|Power - Red| O_VCC
    GND ---|Ground - Black| O_GND

    %% I2C Connections
    P21 ---|I2C SDA - Blue| O_SDA
    P22 ---|I2C SCL - Yellow| O_SCL

    %% Button Connections
    P25 ---|Signal - Green| U_P1
    GND2 ---|Ground - Black| U_P2

    P26 ---|Signal - Orange| D_P1
    GND2 ---|Ground - Black| D_P2

    P27 ---|Signal - Cyan| A_P1
    GND2 ---|Ground - Black| A_P2

    classDef pwr fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#c62828;
    classDef gnd fill:#eceff1,stroke:#37474f,stroke-width:2px,color:#37474f;
    classDef i2c fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#1565c0;
    classDef btn fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#2e7d32;

    class 3V3,O_VCC pwr;
    class GND,GND2,O_GND,U_P2,D_P2,A_P2 gnd;
    class P21,P22,O_SDA,O_SCL i2c;
    class P25,P26,P27,U_P1,D_P1,A_P1 btn;
````

### Wiring Table

| Component          | Component Pin | ESP32 Pin | Wire Color | Function           |
| ------------------ | ------------- | --------- | ---------- | ------------------ |
| **OLED Display**   | VCC           | 3V3       | 🔴 Red     | 3.3V Power         |
|                    | GND           | GND       | ⚫ Black   | Ground             |
|                    | SDA           | GPIO 21   | 🔵 Blue    | I2C Data           |
|                    | SCL           | GPIO 22   | 🟡 Yellow  | I2C Clock          |
| **Button UP**      | Leg 1         | GPIO 25   | 🟢 Green   | Navigation Up      |
|                    | Leg 2         | GND       | ⚫ Black   | Internal pull-up   |
| **Button DOWN**    | Leg 1         | GPIO 26   | 🟠 Orange  | Navigation Down    |
|                    | Leg 2         | GND       | ⚫ Black   | Internal pull-up   |
| **Button APPROVE** | Leg 1         | GPIO 27   | 🔵 Cyan    | Action / Interrupt |
|                    | Leg 2         | GND       | ⚫ Black   | Internal pull-up   |

### Pin Usage Summary

| Category                       | Pins                                                     | Count |
| ------------------------------ | -------------------------------------------------------- | ----- |
| 🔴 **Power**                   | 3V3, VIN, GND ×2                                         | 4     |
| 🔵 **I2C (OLED)**              | GPIO 21 (SDA), GPIO 22 (SCL)                             | 2     |
| 🟢 **Buttons**                 | GPIO 25, GPIO 26, GPIO 27                                | 3     |
| ⬜ **Available for expansion** | GPIO 2, 4, 5, 12, 13, 14, 15, 16, 17, 18, 19, 23, 32, 33 | 14    |
| 🔒 **Input-only**              | GPIO 34, 35, 36 (VP), 39 (VN)                            | 4     |
| ⚙️ **Serial (reserved)**       | GPIO 1 (TX0), GPIO 3 (RX0)                               | 2     |
| 🔄 **System**                  | EN (Reset)                                               | 1     |

> **💡 No external resistors needed.** All buttons use the ESP32's built-in `INPUT_PULLUP` resistors. Just wire button → GPIO and button → GND.

---

## 🧠 How It Works

### Boot Sequence

```
Power On
  │
  ├─ 1. Initialize OLED display → Show boot splash
  ├─ 2. Initialize buttons (Bounce2 debouncing)
  ├─ 3. Initialize NVS credential store
  ├─ 4. Initialize crypto engine (mbedTLS ECDSA P-256)
  ├─ 5. Initialize TOTP engine (HMAC-SHA1)
  ├─ 6. Try WiFi networks in order → Connect first available → NTP sync → Disconnect
  ├─ 7. Start BLE stack (NimBLE FIDO2 GATT service)
  │
  └─ 8. Enter Main Loop → TOTP View
```

### State Machine

```
                    ┌──────────────────────┐
                    │     STATE: BOOT      │
                    │  Splash → NTP → BLE  │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
              ┌────│   STATE: VIEW_TOTP    │────┐
              │    │ Show code + countdown  │    │
              │    └──────────┬───────────┘    │
              │               │                 │
         UP/DOWN         BLE Request       Long-press
         buttons          arrives          APPROVE
              │               │                 │
              │    ┌──────────▼───────────┐    │
              └───►│  STATE: FIDO_PROMPT   │    │
                   │ Show domain + timer   │    │
                   └──────────┬───────────┘    │
                              │                 │
                 ┌────────────┼────────────┐    │
                 │            │            │    │
            APPROVE     Auto-Allow     Timeout  │
             press         ON           30s     │
                 │            │            │    │
                 └────────────┼────────────┘    │
                              │                 │
                    Sign & Return to TOTP  ◄────┘
                    (or toggle auto mode)
```

### FIDO2 Passkey Lifecycle

**Registration (MakeCredential):**

```
Website ──challenge + rpId──► ESP32 (BLE)
ESP32:  Generate ECDSA P-256 keypair
ESP32:  Store {privateKey, rpId, userId, credentialId} → NVS
ESP32:  Return {publicKey, credentialId, attestation} → Website
Website: Store publicKey on server
```

**Authentication (GetAssertion):**

```
Website ──challenge + rpId──► ESP32 (BLE)
ESP32:  Lookup privateKey by rpId in NVS
ESP32:  Wait for APPROVE button (or auto-approve)
ESP32:  Sign challenge with privateKey (ECDSA P-256)
ESP32:  Return {signature, credentialId} → Website
Website: Verify signature → Access Granted ✅
```

> **🔐 The private key NEVER leaves the ESP32.** Only signatures are transmitted.

### TOTP Code Generation (RFC 6238)

```
UTC Time ──÷ 30s──► Time Counter
                        │
Secret (Base32) ────────┤
                        ▼
              HMAC-SHA1(secret, counter)
                        │
                        ▼
              Dynamic Truncation (RFC 4226)
                        │
                        ▼
              6-digit Code (e.g., 837291)
```

---

## 🏗️ Architecture & Tech Stack

| Layer            | Technology              | Purpose                          |
| ---------------- | ----------------------- | -------------------------------- |
| **Framework**    | PlatformIO + Arduino    | Build system & HAL               |
| **Display**      | U8g2 v2.36              | SSD1306 OLED rendering engine    |
| **Buttons**      | Bounce2 v2.72           | Hardware debouncing + long-press |
| **BLE**          | NimBLE-Arduino v2.5     | Lightweight Bluetooth stack      |
| **TOTP**         | mbedTLS HMAC-SHA1       | RFC 6238 code generation         |
| **FIDO2 Crypto** | mbedTLS ECDSA P-256     | Key generation, signing, SHA-256 |
| **Storage**      | ESP32 NVS (Preferences) | Credential persistence           |
| **Time**         | NTP via `configTime()`  | UTC synchronization              |

### Project Structure

```
auth-esp32/
├── platformio.ini                    # Build config, libraries, board settings
├── circuit.png                       # Full pinout circuit diagram
├── README.md                         # This file
└── src/
    ├── config.h                      # Pin defs, WiFi creds, all constants
    ├── main.cpp                      # Boot sequence + state machine
    ├── ui.h / ui.cpp                 # OLED renderer (6 screen modes)
    ├── buttons.h / buttons.cpp       # Debounced input + long-press
    ├── totp.h / totp.cpp             # HMAC-SHA1 TOTP engine
    ├── ntp_sync.h / ntp_sync.cpp     # WiFi → NTP → disconnect
    ├── credential_store.h / .cpp     # NVS database (FIDO2 + TOTP)
    └── fido2/
        ├── crypto.h / crypto.cpp     # ECDSA P-256 (mbedTLS v2.x)
        ├── ble_transport.h / .cpp    # NimBLE FIDO2 GATT (UUID 0xFFFD)
        └── ctap2.h / ctap2.cpp       # CTAP2 command handler
```

### Memory Usage

```
RAM:   [==        ]  17.6%  (57,608 / 327,680 bytes)  — 270KB free
Flash: [========  ]  80.1%  (1,050,085 / 1,310,720 bytes) — 260KB free
```

---

## 🛠️ Prerequisites

### Hardware

| Component                | Specification                 | Quantity |
| ------------------------ | ----------------------------- | -------- |
| ESP32-WROOM-32 DevKit V1 | 30-pin variant, 4MB flash     | 1        |
| 0.96" OLED Display       | SSD1306 / SH1106, I2C, 128×64 | 1        |
| Tactile Push Buttons     | 6mm × 6mm, 4-pin              | 3        |
| Breadboard               | Full-size or half-size        | 1        |
| Jumper Wires             | Male-to-male                  | ~10      |
| Micro-USB Cable          | For programming + power       | 1        |

### Software

| Tool                | Version        | Install                           |
| ------------------- | -------------- | --------------------------------- |
| **PlatformIO Core** | 6.x+           | `pipx install platformio`         |
| **Python**          | 3.8+           | System package manager            |
| **USB Driver**      | CP2102 / CH340 | Depends on your DevKit's USB chip |

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/auth-esp32.git
cd auth-esp32
```

### 2. Configure WiFi Networks

Edit `src/config.h` — add your WiFi networks (up to 5). The device tries each in order and connects to the **first available** one:

```cpp
const WiFiCredential WIFI_CREDENTIALS[] = {
    { "Home_WiFi",       "home_password"     },  // Tried first
    { "Office_WiFi",     "office_pass_123"   },  // Fallback
    { "Phone_Hotspot",   "hotspot_pass"      },  // Emergency fallback
};
```

> **💡 Multi-WiFi Fallback:** If your primary network is down, the device automatically tries the next one. Great for switching between home, office, and mobile hotspot.

### 3. (Optional) Adjust Timezone

Default is IST (UTC+5:30). Change `NTP_GMT_OFFSET` in `src/config.h`:

```cpp
#define NTP_GMT_OFFSET  19800   // IST = +5:30 = 19800 seconds
// Examples:
//   UTC:    0
//   EST:   -18000  (UTC-5)
//   PST:   -28800  (UTC-8)
//   CET:    3600   (UTC+1)
//   JST:    32400  (UTC+9)
```

### 4. Wire the Circuit

Follow the [circuit diagram](#-circuit-diagram--full-30-pin-pinout) above. Quick summary:

- OLED: VCC→3V3, GND→GND, SDA→GPIO21, SCL→GPIO22
- Buttons: Each button → respective GPIO + GND (no resistors needed)

### 5. Build the Firmware

```bash
# Install PlatformIO if not already installed
pipx install platformio

# Build (first build downloads ESP32 toolchain + libraries automatically)
pio run
```

Expected output:

```
RAM:   [==        ]  17.6% (used 57608 bytes from 327680 bytes)
Flash: [========  ]  80.1% (used 1050085 bytes from 1310720 bytes)
============= [SUCCESS] =============
```

### 6. Flash to ESP32

```bash
# Connect ESP32 via USB, then:
pio run -t upload
```

> **💡 Tip:** If upload fails, hold the **BOOT** button on the ESP32 while uploading, then release after "Connecting..." appears.

### 7. Open Serial Monitor

```bash
pio device monitor
```

You'll see the full boot sequence:

```
========================================
  AuthKey-ESP32 v1.0.0-alpha
  Hardware Authenticator
========================================

[UI] OLED initialized.
[MAIN] Buttons initialized.
[CRED] Initializing NVS credential store...
[CRED] Loaded: 0 FIDO2 credentials, 0 TOTP accounts
[CRYPTO] Engine initialized (ECDSA P-256 via mbedTLS).
[TOTP] Engine initialized.
[MAIN] Pre-loaded demo TOTP account.
[NTP] Connecting to WiFi...
[NTP] WiFi connected. IP: 192.168.1.42
[NTP] Time synced: 2026-04-29 15:30:00
[NTP] WiFi disconnected. Running offline.
[BLE] Initializing NimBLE FIDO2 stack...
[BLE] FIDO2 GATT service created.
[BLE] Advertising as: AuthKey-ESP32
[MAIN] Entering main loop. Ready.
```

---

## 🎮 Usage

### Button Controls

| Button      | Short Press           | Long Press (1.5s)        |
| ----------- | --------------------- | ------------------------ |
| **UP**      | Previous TOTP account | —                        |
| **DOWN**    | Next TOTP account     | —                        |
| **APPROVE** | Approve FIDO2 request | Toggle Auto-Allow ON/OFF |

### OLED Screen Layout

```
┌────────────────────────────┐
│ [MANUAL]           BLE     │ ← Status Bar
├────────────────────────────┤
│ GitHub (1/3)               │ ← Account Name
│                            │
│        837 291             │ ← TOTP Code (large)
│                            │
│ ████████████░░░░ 18s       │ ← Countdown Bar
├────────────────────────────┤
│ <UP  DOWN>       [APPROVE] │ ← Navigation Bar
└────────────────────────────┘
```

### Adding TOTP Accounts

Currently, TOTP accounts are added programmatically. In `src/main.cpp`, the demo account uses the Base32 secret `GEZDGNBVGY3TQOJQ`. To add your own accounts:

```cpp
// In setup(), after credStoreInit():
credStoreSaveTotp("GitHub", "YOUR_BASE32_SECRET_HERE");
credStoreSaveTotp("Google", "ANOTHER_BASE32_SECRET");
```

> **💡 How to get the Base32 secret:** When setting up 2FA on a website, look for "Can't scan QR code?" or "Manual entry" — it will show a Base32-encoded key.

### Using as a FIDO2 Security Key

1. The device advertises as `AuthKey-ESP32` over Bluetooth
2. On your laptop/phone, go to a WebAuthn-enabled site (e.g., `webauthn.io`)
3. Choose "Add Security Key" → Select Bluetooth
4. Pair with `AuthKey-ESP32`
5. The OLED will show the registration/login prompt
6. Press APPROVE (or let Auto-Allow handle it)

---

## 🔧 Build Commands Reference

| Command                                   | Description                       |
| ----------------------------------------- | --------------------------------- |
| `pio run`                                 | Compile firmware                  |
| `pio run -t upload`                       | Compile + flash to ESP32          |
| `pio run -t clean`                        | Clean build artifacts             |
| `pio device monitor`                      | Open serial monitor (115200 baud) |
| `pio run -t upload && pio device monitor` | Flash + monitor in one command    |
| `pio lib list`                            | List installed libraries          |
| `pio boards \| grep esp32`                | List available ESP32 boards       |

---

## 📊 FIDO2 BLE Protocol Details

### GATT Service

| Element                 | UUID                                   | Properties       |
| ----------------------- | -------------------------------------- | ---------------- |
| **FIDO Service**        | `0xFFFD`                               | Primary Service  |
| FIDO Control Point      | `F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623B3` | Write            |
| FIDO Status             | `F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623B3` | Notify           |
| Control Point Length    | `F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623B3` | Read             |
| **Device Info Service** | `0x180A`                               | Standard BLE DIS |

### Supported CTAP2 Commands

| Command                       | Code   | Description                      |
| ----------------------------- | ------ | -------------------------------- |
| `authenticatorGetInfo`        | `0x04` | Report device capabilities       |
| `authenticatorMakeCredential` | `0x01` | Register a new passkey           |
| `authenticatorGetAssertion`   | `0x02` | Authenticate with stored passkey |

### Credential Storage Capacity

| Type           | Max Count | Key Size              | Storage Per Entry |
| -------------- | --------- | --------------------- | ----------------- |
| FIDO2 Passkeys | 200       | 32B (P-256 private)   | ~256 bytes        |
| TOTP Accounts  | 20        | ≤32B (decoded secret) | ~96 bytes         |

---

## ⚠️ Security Considerations

| Aspect             | Phase 1 (Current)                  | Production Recommendation                       |
| ------------------ | ---------------------------------- | ----------------------------------------------- |
| **Key Storage**    | Plain NVS (unencrypted flash)      | Enable ESP32 Flash Encryption + NVS Encryption  |
| **Secure Element** | None (keys in flash)               | Add ATECC608A for tamper-resistant key storage  |
| **Attestation**    | Self-attestation (empty `attStmt`) | Full packed attestation with device certificate |
| **PIN Protocol**   | Not implemented                    | CTAP2 PIN/UV auth protocol                      |
| **Secure Boot**    | Disabled                           | Enable ESP32 Secure Boot v2                     |
| **Transport**      | BLE with bonding                   | BLE with bonding + MITM protection              |

> **⚠️ This is a Phase 1 development prototype.** It demonstrates the full FIDO2 flow but should NOT be used as your sole authentication factor for critical accounts without the production security hardening listed above.

---

## 🗺️ Roadmap

### Phase 2

- [ ] CTAP2 PIN protocol support
- [ ] Credential management commands (list/delete from device UI)
- [ ] Full CBOR library (tinycbor) for robust parsing
- [ ] NVS encryption for key-at-rest protection
- [ ] External RTC module (DS3231) for offline time persistence
- [ ] USB HID transport (CTAP2 over USB)

### Phase 3

- [ ] ATECC608A secure element integration
- [ ] Secure Boot + Flash Encryption
- [ ] Full FIDO2 conformance test suite
- [ ] 3D-printed enclosure with button cutouts
- [ ] Battery + deep sleep power management
- [ ] Web-based configuration portal (WiFi AP mode)

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) — Lightweight BLE stack
- [U8g2](https://github.com/olikraus/u8g2) — Universal display driver
- [Bounce2](https://github.com/thomasfredericks/Bounce2) — Button debouncing
- [FIDO Alliance](https://fidoalliance.org/specifications/) — CTAP2/WebAuthn specs
- [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) — TOTP algorithm
- [mbedTLS](https://tls.mbed.org/) — Cryptographic primitives

---

<p align="center">
  <b>Built with ⚡ on ESP32</b><br>
  <sub>No cloud. No phone. No trust required.</sub>
</p>
]]></description>
