# AuthKey-ESP32

A standalone hardware authenticator on an ESP32 dev board with a 128×64 OLED and
a few buttons:

- **TOTP codes** (RFC 6238; SHA-1/256/512, 6 or 8 digits) shown on the OLED.
- **FIDO2 / passkey security key**: register and sign in to websites.
  - **Hybrid** (the "Use a phone or tablet" QR flow): works with Windows 11,
    Chrome and Edge. **No phone needed**: a small PC helper reads the QR off
    your screen and hands it to the device.
  - **Bluetooth security key** (CTAP over BLE): pair once, then pick
    "Security key". Works on Android, ChromeOS, Linux/macOS Chrome, and
    Windows 10 (Windows 11 support for BLE keys is inconsistent).
  - **USB security key** on Windows, through the PC service and usbip-win2.
- Every registration and sign-in is approved **on the device** with the OK
  button. An optional on-device PIN adds user verification.
- **Bluetooth keyboard**: press OK on a code to type it into the paired PC or
  phone.
- **Walk-away lock** for Windows (and Android, as a trusted device), plus
  automatic Windows sign-in when you come back.
- **Web page** on your network for the event log, campus login, passkeys and
  authenticator accounts.
- **Encrypted backups** of everything that can't be recreated.
- **Campus WiFi auto-login** (IIT Guwahati) for the whole network behind
  your router.

## Hardware

| Part | Notes |
| --- | --- |
| ESP32-WROOM-32 DevKit (4 MB) | CP2102 or CH340 USB bridge |
| 0.96" SSD1306 OLED, I²C | For a 1.3" SH1106, set `OLED_DRIVER` in `src/config.h` |
| 3–5 push buttons | Wired between GPIO and GND, using internal pull-ups |

| Signal | GPIO |
| --- | --- |
| OLED SDA / SCL | 21 / 22 (VCC → 3V3, GND → GND) |
| UP / DOWN / OK | 25 / 26 / 27 |
| LEFT / RIGHT (optional) | 32 / 33 |

![Pinout](./circuit.png)

**Windows driver:** if the board doesn't show up as a COM port, install the
[Silicon Labs CP210x driver](https://www.silabs.com/developer-tools/usb-to-uart-bridge-vcp-drivers)
(or the CH340 driver, depending on your board).

## Build & flash

```bash
cp .env.example .env                       # add your WiFi networks (and OTA password)
pio run -t upload                          # build + flash over USB
pio device monitor                         # serial console (type: help)
```

The first boot after upgrading from v1 changes the partition layout. Erase the
flash once with `pio run -t erase` before uploading.

WiFi is used for the clock (NTP), for hybrid sign-ins, and for optional OTA
updates. Without WiFi, TOTP still works once the clock is set (`time set <unix>`).

All secrets live in `.env` (git-ignored): `WIFI_<n>_SSID` / `WIFI_<n>_PASSWORD`,
`OTA_PASSWORD`, `OTA_HOST` and `IITG_USERNAME` / `IITG_PASSWORD` (campus
auto-login, below). `scripts/env_secrets.py` reads it at build
time, so nothing secret is kept in `src/`.

**Updates over WiFi (OTA):** set `OTA_PASSWORD` in `.env`, flash once over
USB, then update wirelessly with `pio run -e ota -t upload` (password and
host come from `.env`). Leave `OTA_PASSWORD` empty to keep OTA off.

## Using it

### Controls

| Where | Action |
| --- | --- |
| Home (TOTP) | UP/DOWN switch account · **OK types the code** (Bluetooth keyboard) · hold OK → menu |
| Menus | UP/DOWN move · OK select · hold OK (or LEFT) back |
| Passkey / pairing / backup / web prompt | **OK approve** · DOWN deny |
| PIN entry | UP/DOWN change digit · OK next digit · hold OK submit · hold UP delete |

The menu has: Passkeys (list/delete), Auto-approve, Device PIN, WiFi,
Campus net, Bluetooth (keyboard on/off, forget pairings), Event log, Device
info (shows the web page address), Reset passkeys.

### TOTP accounts

Add accounts over USB with the serial console, or with the helper script:

```bash
.venv/Scripts/python tools/authkey.py totp uri "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
.venv/Scripts/python tools/authkey.py totp add "My Bank" JBSWY3DPEHPK3PXP
.venv/Scripts/python tools/authkey.py totp list
```

(`otpauth://` URIs are the text inside a site's QR code. Most authenticator
setup pages also show the secret as text.)

Easier: with the QR helper running (below) and the device on USB, just open
the site's "set up authenticator app" page. The helper spots the QR and adds
the account to the device by itself (once per QR); then type the code shown
on the OLED to finish the site's setup.

### Passkeys without a phone (hybrid, recommended on Windows 11)

1. Keep the device on WiFi and the PC's Bluetooth on.
2. Run the helper on the PC. To start it hidden at every login (shows as
   "AuthKey QR helper" in Task Manager, log in
   `%LOCALAPPDATA%\AuthKey\qr_bridge.log`):

   ```powershell
   pc\build.ps1                                                    # builds pc\bin\AuthKeyQR.exe
   powershell -ExecutionPolicy Bypass -File tools\autostart.ps1    # -Remove to undo
   ```

   Or run it in a terminal: `.venv/Scripts/python tools/qr_bridge.py`.

3. On a website, choose to create or use a passkey, then
   **"Use a phone or tablet" / "iPhone, iPad or Android device"**.
   Windows shows a QR code. The helper spots it and sends it to the device over
   USB, or over Bluetooth if the device isn't plugged in.
4. The device connects through the FIDO tunnel and shows **REGISTER** or
   **SIGN IN** with the site name. Press **OK**.

### Type codes with the Bluetooth keyboard

The device is also a Bluetooth keyboard. Pair **AuthKey-ESP32** with your PC
or phone (the OLED shows a 6-digit code: press OK if it matches), click into
the code field, then press **OK** on the code screen: the device types the
current code. It types into every paired host that is connected. Turn the
keyboard off (or on) in **Menu → Bluetooth → OK**; the device restarts.

If the PC was paired before the keyboard existed, remove AuthKey-ESP32 in
Windows Bluetooth settings and pair it again, so Windows picks up the keyboard.

On Android a connected hardware keyboard hides the on-screen keyboard. To
keep it, turn on Settings → System → Keyboard → Physical keyboard →
*Show on-screen keyboard*.

### Passkeys over Bluetooth (security-key mode)

Pair "AuthKey-ESP32" in your OS Bluetooth settings. The OLED shows a 6-digit
code; press OK if it matches the PC. Then choose "Security key" when a site
asks for a passkey.

### Passkeys over USB ("Security key" on Windows)

With the Windows service installed (see *Windows sign-in* below) and
[usbip-win2](https://github.com/vadimgrn/usbip-win2/releases) installed, the
plugged-in AuthKey also shows up as a normal USB FIDO security key. When a site
asks for a passkey, pick **Security key**. The service presents a virtual
USB HID key over USB/IP on 127.0.0.1 and forwards each CTAP request to the
device over its serial port. The key attaches when the board is plugged in
and detaches when it's unplugged. To turn it off, create
`C:\ProgramData\AuthKey\no-virtual-key` and restart the service.

### Firefox

Firefox on Windows uses the same Windows passkey dialog as Chrome and Edge,
so everything above works the same: **Security key** (Bluetooth or USB) and
**"Use a phone or tablet"** (the QR helper spots the QR in any browser).

### Android

Pair AuthKey-ESP32 with the phone (it pairs as a keyboard; press OK on the
AuthKey when the codes match), then install the companion app in `android/`:

```bash
cd android
./gradlew assembleDebug        # needs JDK 17 (Android Studio's, or set JAVA_HOME)
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

The app (Kotlin, Android 9+):

- **Passkeys, Android 14+:** turn on AuthKey under *Passkey provider
  settings*. Android's passkey sheet (Chrome, apps) then offers **AuthKey
  security key**. The app talks CTAP to the AuthKey over **Bluetooth**, or
  over **USB** when it's plugged into the phone (USB-C/OTG cable, CP2102
  boards). You approve on the AuthKey as usual. Android reserves the standard
  FIDO Bluetooth service for its system apps, so the firmware offers the same
  channel on its own service (`A3C87504/05`), encrypted links only.
- **Passkeys via QR, any version:** like the Windows helper, a passkey QR
  ("Use a phone or tablet" / "Use another device") makes the AuthKey sign in
  the way a phone would (over its WiFi). Point the app's camera at a QR on any
  computer or phone. For a QR on the phone's own screen, use the **AuthKey
  QR** Quick Settings tile, or share a screenshot to AuthKey. Authenticator
  (`otpauth://`) QRs are added to the AuthKey's codes when it is on USB.
- **Walk-away lock:** locks the phone after the AuthKey has been out of range
  for 15 s (configurable), with the same rules as on Windows: it only locks
  after seeing the AuthKey nearby, and unlocking with your PIN while it's
  away doesn't lock again. Two lock methods; turn on one:
  *Normal* (Accessibility) locks like the power button, so fingerprint still
  works; *Strict* (device admin) needs the PIN after each lock. On Android 13+,
  sideloaded apps need App info → ⋮ → *Allow restricted settings* first.
- **Keep running:** the lock runs as a service with a permanent
  notification. The app asks to be excluded from battery optimisation.
  Samsung phones also need Settings → Battery → Background usage limits →
  *Never sleeping apps* → AuthKey.

Without the app, Android's own **Extend Unlock → Trusted devices** (Smart
Lock) can keep the phone unlocked while the AuthKey is connected, and the
keyboard types TOTP codes into apps too.

### Device PIN (user verification)

Set a 4–8 digit PIN in **Menu → Device PIN**. Sites that ask for user
verification then make you enter the PIN on the device. After 8 wrong
attempts, user verification is blocked until you reset the passkeys.

### Windows sign-in (unlock the PC)

The device can sign you in to Windows: wake the lock screen and, if the
AuthKey is reachable, you're signed in without a PIN, face or password.
It works over **USB, Bluetooth and WiFi**, whichever answers first.

```powershell
pc\build.ps1                      # builds pc\bin (Visual Studio C++ tools + .NET 9 SDK)
# then, in an Administrator PowerShell, with the device on USB:
pc\install.ps1                    # installs, pairs (press OK on the device), tests
```

Pairing asks for your Windows account **password**. For a Microsoft account
that's the account.microsoft.com password, not the Hello PIN. It is stored
encrypted (DPAPI) in `C:\ProgramData\AuthKey`, readable only by SYSTEM and
Administrators, and is released to the lock screen only after the device
answers a fresh random challenge (HMAC-SHA256 with a per-PC key).

- With auto-approve **on**, the device answers by itself. With it **off**, the
  OLED asks "UNLOCK PC?" and you press OK.
- USB means "unlocked whenever plugged in". WiFi works whenever the device is
  on the same network. Bluetooth works within about 10 m. Turn
  transports on or off with
  `"C:\Program Files\AuthKey\AuthKeyUnlock.exe" set usb|bluetooth|wifi on|off`.
- Your normal PIN, face and password sign-in stay available. If Windows ever
  rejects the stored password (e.g. you changed it), automatic sign-in pauses;
  sign in normally and run `AuthKeyUnlock.exe pair` again.
- Log: `C:\ProgramData\AuthKey\logs\service.log` (readable without admin).
  For a per-packet USB key trace, create `C:\ProgramData\AuthKey\vk-trace`.
- Emergency off-switch: create the file `C:\ProgramData\AuthKey\disabled`.
  Remove everything with `pc\uninstall.ps1 -Purge`.

### Lock the PC when you walk away

The PC helper (the one that reads QR codes, `tools/qr_bridge.py`) watches
the AuthKey's Bluetooth signal; the device advertises all the time, even while
connected. When the AuthKey has been out of range for 20 s, the PC locks,
as if you pressed Win+L. Come back and the AuthKey signs you in again
(*Windows sign-in* above).

- It only locks after it has seen the AuthKey nearby, and each lock disarms
  it until the AuthKey is nearby again. So if you sign in with your Windows
  PIN while the AuthKey is away, the PC stays unlocked (no lock loop) until
  the AuthKey comes back.
- Settings in `%LOCALAPPDATA%\AuthKey\helper.json`: `auto_lock`,
  `away_seconds` (20), `min_rssi` (-85 dBm: a weaker signal counts as away;
  raise it towards -70 to lock sooner). Restart the helper after editing
  (`tools\autostart.ps1`). `python tools/presence.py watch` shows the live
  signal without locking. `qr_bridge.py --no-lock` turns it off.
- Flashing the device over USB takes it off the air for about a minute, so
  the PC locks; sign in with your PIN (the lock won't loop).

### Campus WiFi auto-login (IITG)

IIT Guwahati's firewall (`agnigarh.iitg.ac.in:1442`) signs you out after a
while unless the login page is kept open. With `IITG_USERNAME` /
`IITG_PASSWORD` in `.env`, the device does that job for the whole network
behind your router:

- Every 2 min it checks the internet. If it's down, it logs in (it fetches a
  fresh form from `/login?` and posts it, as the browser does). If it's up
  through someone else's login, it takes the session over so it can keep it.
- It refreshes its session every 20 min (`/keepalive`), well inside the
  30-min window, so the network never drops.
- The portal's certificate is verified (DigiCert root), so the password is
  only ever sent to the real portal. It is never logged.
- "Session limit" replies make it wait and retry every 5 min until a slot is
  free. Rejected logins back off to every 30 min after 3 tries (no lockout).
- If NTP is blocked while logged out, the clock is taken from the HTTP `Date`
  header.

**Menu → Campus net** shows the state, last result and refresh countdown,
and has **Login now**, **Logout** (pauses auto-login until you log in
again) and the **Auto-login ON/off** switch. The home screen shows
`IITG ✓ 14m` next to the clock while online (14 min to the next refresh),
`!NET` while the network needs a login and `IITG-` while paused. Serial:
`portal status|login|logout|on|off`. Every login, drop and failure is in the
event log with its time (`14:39 IITG session lost`), so you can see when and
how often the campus ends sessions.

The PC helper shows a Windows notification when the campus internet drops,
comes back, or the login is stuck (session limit, rejected password). If
Windows notifications are turned off (Settings → System → Notifications), it
shows a small pop-up that closes itself instead. `qr_bridge.py --no-notify`
turns this off.

### Web page

`http://authkey-esp32.local/` (or the IP shown in **Menu → Device info**)
from any browser on the same network, phones included:

- Anyone on the network sees only the device status and campus-login state.
- **Allow this browser** shows "ALLOW WEB ACCESS?" on the OLED; press OK.
  For 12 hours that browser gets the event log, campus Login/Logout and the
  auto-login switch, the passkey and authenticator lists (delete, add an
  `otpauth://` link) and the phone sign-in box. Sessions live in RAM, are
  tied to the browser's IP and end on reboot or with **Lock this browser**.
- Codes and secrets are never shown on the page.

### Backup and restore

Every passkey is derived from a master key inside the device: if the board
dies, they're gone. Make a backup once, and again after adding passkeys or
accounts:

```bash
.venv/Scripts/python tools/authkey.py backup authkey-backup.json
.venv/Scripts/python tools/authkey.py restore authkey-backup.json   # onto a new or reset board
```

The backup holds the master key, passkey records, signature counter, TOTP
accounts and paired PCs. It is encrypted with AES-256-GCM under a key made
from your passphrase (PBKDF2-SHA256, 600 000 rounds). Only that derived key
goes over USB, never the passphrase. Both directions must be confirmed on the
OLED, with the device PIN if one is set. Restoring replaces everything,
moves the signature counter forward (so sites never see it go back) and
restarts the device. Keep the file and the passphrase in separate places.

### Event log

**Menu → Event log**, `log` on the serial console, or the web page. Each line
is stamped with the time (or `+M:SS` since boot before the clock is set). The
log survives reboots, crashes and power cuts. Each boot logs why the last one
ended (`Boot v2.0.0 (crash)`, `(power on)`, `(restart)`). `log clear` empties it.

## Serial console

`help` lists everything. Highlights: `status`, `totp …`, `wifi add <ssid> <pass>`,
`passkeys`, `tz <POSIX TZ>`, `auto on|off`, `hybrid <FIDO:/…>`, `portal …`,
`log`, `log clear`, `kbd`, `kbd on|off`, `kbd type <n>`.

## Security notes

- Private keys are never stored. Each credential ID is MAC-protected and binds
  a random nonce to the site, and the key is re-derived from a 32-byte device
  master key. Discoverable passkeys store only the user name/ID for listing.
- The master key lives in NVS flash **unencrypted**. Someone with physical
  access could dump the flash and clone your keys. ESP32 flash encryption and
  secure boot would fix this, but they burn eFuses irreversibly, so they're
  left to you.
- **Auto-approve** (off by default) makes sign-ins and passkey registrations
  hands-free: no button press. If a device PIN is set, sites that require
  user verification (Google, Microsoft, ...) ask for the PIN **once**; the
  device then stays *unlocked* for 12 hours (`uvhours <n>`, 0 = until reboot)
  and verifies hands-free, like an unlocked phone. `lock` ends the session.
  Without a PIN the device reports "not verified", which works for sites that
  only *prefer* verification, but Google then treats the key as a
  2-Step-Verification-only key. With the QR helper running, any site asking
  for this passkey on your PC gets signed in while the device is unlocked.
- OTA is **off** unless `OTA_PASSWORD` is set in `.env`. Anyone who can flash
  firmware can read your keys, so use a long random password and trusted WiFi.
- The `test` build (`pio run -e test`) adds console commands that let software
  on the PC approve requests (`approve!` even skips the PIN for backup
  prompts). Use it only for running the tests.
- The web page is plain HTTP on your local network: an approved browser
  session could be sniffed by someone else on the same WiFi. It never shows
  codes or secrets, but it can delete passkeys and log the campus session
  out. Lock the browser session when you're done on a shared network.

## Tests

With the **test** build flashed:

```bash
python -m venv .venv
.venv/Scripts/pip install fido2 pyserial cryptography websockets bleak pyotp cbor2
.venv/Scripts/python tools/test_device.py     # CTAP2 + TOTP, verified by python-fido2's RP server
.venv/Scripts/python tools/hybrid_sim.py      # full hybrid flow via the real tunnel + PC Bluetooth
```

Flash the normal build afterwards: `pio run -t upload`.

## Layout

```text
src/
  main.cpp               setup + cooperative main loop
  config.h               pins and constants (secrets: .env via scripts/env_secrets.py)
  core/                  event log (persistent), settings, PIN, on-device approvals, backup
  crypto/                mbedTLS wrappers (P-256, AES-GCM, HKDF, ...)
  util/                  CBOR reader/writer, hex/base32, FIDO QR digits
  fido/                  CTAP 2.0 engine, credential derivation & storage
  transport/ble.*        NimBLE: FIDO BLE service, keyboard, pairing, hybrid adverts
  transport/hybrid.*     caBLE v2: tunnel, Noise KNpsk0, encrypted CTAP
  net/                   WiFi/NTP/OTA, campus portal login, web page, WebSocket client, root CAs
  totp/                  TOTP storage and generation
  ui/                    OLED screens, buttons
  cli/                   USB serial console
tools/                   PC helpers (QR, walk-away lock, notifications, backup) and tests
android/                 Android app (Kotlin): passkeys over BLE/USB, QR, walk-away lock
partitions.csv           2 × 1.875 MB OTA slots + 128 KB NVS
```
